package Net::Google::SafeBrowsing4;

use strict;
use warnings;

use Carp;
use LWP::UserAgent;
use URI;
use Digest::SHA qw(sha256);
use List::Util qw(first);
use Text::Trim;
use MIME::Base64;
use String::HexConvert;
use IO::Socket::SSL 'inet4';
use Data::Dumper;
use JSON::XS;
use Time::HiRes qw(time);

use Exporter 'import';
our @EXPORT = qw(DATABASE_RESET INTERNAL_ERROR SERVER_ERROR NO_UPDATE NO_DATA SUCCESSFUL);


BEGIN {
    IO::Socket::SSL::set_ctx_defaults(
#         verify_mode => Net::SSLeay->VERIFY_PEER(),
# 			SSL_verify_mode => 0,
    );
}

our $VERSION = '0.1';


=head1 NAME

Net::Google::SafeBrowsing4 - Perl extension for the Google Safe Browsing v4 API. (Google Safe Browsing v3 has been deprecated by Google.)

=head1 SYNOPSIS

  use Net::Google::SafeBrowsing4;
  use Net::Google::SafeBrowsing4::File;
  
  my $storage = Net::Google::SafeBrowsing4::File->new(path => '.');
  my $gsb = Net::Google::SafeBrowsing4->new(
	  key 	=> "my key", 
	  storage	=> $storage,
  );
  
  $gsb->update();
  my @matches = $gsb->lookup(url => 'http://ianfette.org/');
  
  if (scalar @matches > 0) {
	  print "http://ianfette.org/ is flagged as a dangerous site\n";
  }

  $storage->close();

=head1 DESCRIPTION

Net::Google::SafeBrowsing4 implements the Google Safe Browsing v4 API.

The library passes most of the unit tests listed in the API documentation. See the documentation (L<https://developers.google.com/safe-browsing/v4/urls-hashing#canonicalization>) for more details about the unit tests.

The Google Safe Browsing database must be stored and managed locally. L<Net::Google::SafeBrowsing4::File> uses files as the storage back-end. Other storage mechanisms (databases, memory, etc.) can be added and used transparently with this module.

The source code is available on github at L<https://github.com/juliensobrier/Net-Google-SafeBrowsing4>.

If you do not need to inspect more than 10,000 URLs a day, you can use Net::Google::SafeBrowsing4::Lookup with the Google Safe Browsing v4 Lookup API which does not require to store and maintain a local database.


IMPORTANT: Google Safe Browsing v4 requires an API key from Google: https://developers.google.com/safe-browsing/v4/get-started.


=head1 CONSTANTS

Several  constants are exported by this module:

=over 4

=item DATABASE_RESET

Google requested to reset (empty) the local database.

=item INTERNAL_ERROR

An internal error occurred.

=item SERVER_ERROR

The server sent an error back to the client.

=item NO_UPDATE

No update was performed, probably because it is too early to make a new request to Google Safe Browsing.

=item NO_DATA

No data was sent back by Google to the client, probably because the database is up to date.

=item SUCCESSFUL

The operation was successful.


=back

=cut

use constant {
	DATABASE_RESET					=> -6,
	INTERNAL_ERROR					=> -3,	# internal/parsing error
	SERVER_ERROR						=> -2, 	# Server sent an error back
	NO_UPDATE								=> -1,	# no update (too early)
	NO_DATA									=> 0, 	# no data sent
	SUCCESSFUL							=> 1,	# data sent
};


=head1 CONSTRUCTOR


=head2 new()

Create a Net::Google::SafeBrowsing4 object

  my $gsb = Net::Google::SafeBrowsing4->new(
		key 	=> "my key", 
		storage	=> Net::Google::SafeBrowsing4::File->new(path => '.'),
		debug	=> 0,
		lists => ["*/ANY_PLATFORM/URL"],
  );

Arguments

=over 4

=item base

Safe Browsing base URL. https://safebrowsing.googleapis.com by default

=item key

Required. Your Google Safe browsing API key

=item storage

Required. Object which handles the storage for the Google Safe Browsing database. See L<Net::Google::SafeBrowsing4::Storage> for more details.

=item lists

Optional. The Google Safe Browsing lists to handle. By default, handles all lists.

=item debug

Optional. Set to 1 to enable debugging. 0 (disabled) by default.

The debug output maybe quite large and can slow down significantly the update and lookup functions.

=item errors

Optional. Set to 1 to show errors to STDOUT. 0 (disabled by default).

=item perf

Optional. Set to 1 to show performance information.

=item version

Optional. Google Safe Browsing version. 4 by default

=back

=cut

sub new {
	my ($class, %args) = @_;

	my $self = { # default arguments
		base		=> 'https://safebrowsing.googleapis.com',
		lists			=> [],
		all_lists	=> [],
		key				=> '',
		version		=> '4',
		debug			=> 0,
		errors		=> 0,
		last_error	=> '',
		perf		=> 0,

		%args,
	};

	if (! exists $self->{storage}) {
		use Net::Google::SafeBrowsing4::Storage;
		$self->{storage} = Net::Google::SafeBrowsing4::Storage->new();
	}
	if (ref $self->{list} ne 'ARRAY') {
		$self->{list} = [$self->{list}];
	}
	
	$self->{base} = join("/", $self->{base}, "v" . $self->{version});

	bless $self, $class or croak "Can't bless $class: $!";
    return $self;
}

=head1 PUBLIC FUNCTIONS


=head2 update()

Perform a database update.

  $gsb->update();

Return the status of the update (see the list of constants above): INTERNAL_ERROR, SERVER_ERROR, NO_UPDATE, NO_DATA or SUCCESSFUL

This function can handle multiple lists at the same time. If one of the list should not be updated, it will automatically skip it and update the other one. It is faster to update all lists at once rather than doing them one by one.


Arguments

=over 4

=item lists

Optional. Update specific lists. Use the list(s) from new() by default. List are in the format "MALWARE/WINDOWS/URLS" or "*/WINDOWS/*" where * means all possible values.


=item force

Optional. Force the update (1). Disabled by default (0).

Be careful if you set this option to 1 as too frequent updates might result in the blacklisting of your API key.

=back

=cut

sub update {
	my ($self, %args) 	= @_;
	my $lists		= $args{lists} || $self->{lists} || [];
	my $force 	= $args{force}	|| 0;
	
	
	# Check if it is too early
	# TODO: some lists may have been updated , others not. Update time has to be by list
	my $time = $self->{storage}->next_update();
	if ($time > time() && $force == 0) {
		$self->debug("Too early to update the local storage\n");
		
		return NO_UPDATE;
	}
	else {
		$self->debug("time for update: $time / ", time());
	}
	
	my $all_lists = $self->make_lists(lists => $lists);
	my $info = {
		client => {
			clientId => 'Net::Google::SafeBrowsing4',
			clientVersion	=> $VERSION
		},
		listUpdateRequests => [ $self->make_lists_for_update(lists => $all_lists) ]
	};
	
	my $last_update = time;
	
	my $response = $self->ua->post($self->{base} . "/threatListUpdates:fetch?key=" . $self->{key}, 
		"Content-Type" => "application/json",
		Content => encode_json($info)
	);
	
	$self->debug($response->request->as_string);
	$self->debug($response->as_string, "\n");
	
	if (! $response->is_success) {
		$self->error("Update request failed\n");

		$self->update_error('time' => time());

		return SERVER_ERROR;
	}
	
	my $result = NO_DATA;
	
	my $json = decode_json($response->content);
	my @data = @{ $json->{listUpdateResponses} };
	
	foreach my $list (@data) {
		my $threat = $list->{threatType};						# MALWARE
		my $threatEntry = $list->{threatEntryType}; # URL
		my $platform = $list->{platformType};				# ANY_PLATFORM
		
		my $update = $list->{responseType};					# FULL_UPDATE

		# save and check the update
		my @hex = ();
		foreach my $addition (@{ $list->{additions} }) {
			my $hashes_b64 = $addition->{rawHashes}->{rawHashes}; # 4 bytes
			my $size = $addition->{rawHashes}->{prefixSize};
		
			my $hashes = decode_base64($hashes_b64); # hexadecimal
			push(@hex, unpack("(a$size)*", $hashes));
		}
		
		my @remove = ();
		foreach my $removal (@{ $list->{removals} }) {
			push(@remove, @{ $removal->{rawIndices}->{indices} });
		}
		
		if (scalar @hex > 0) {
			$result = SUCCESSFUL if ($result >= 0);
			@hex = sort {$a cmp $b} @hex; # lexical sort
			
			my @hashes = $self->{storage}->save(
				list => {
					threatType 			=> $threat,
					threatEntryType	=> $threatEntry,
					platformType		=> $platform
				},
				override	=> $list->{responseType} eq "FULL_UPDATE" ? 1 : 0,
				add				=> [@hex],
				remove 		=> [@remove],
				'state'		=> $list->{newClientState},
			);
			
			
			my $check = trim encode_base64 sha256(@hashes);
			
			if ($check ne $list->{checksum}->{sha256}) {
				$self->error("$threat/$platform/$threatEntry update error: checksum do not match: ", $check, " / ", $list->{checksum}->{sha256});
				$self->{storage}->reset(
					list => {
						threatType 			=> $list->{threatType},
						threatEntryType	=> $list->{threatEntryType},
						platformType		=> $list->{platformType}
					}
				);
				
				$result = DATABASE_RESET;
			}
			else {
				$self->debug("$threat/$platform/$threatEntry update: checksum match");
			}
		}
		
		# TODO: handle caching
	}
	
	
	my $wait = $json->{minimumWaitDuration};
	my $next = time();
	if ($wait =~ /(\d+)(\.\d+)?s/i) {
		$next += $1;
	}

	$self->{storage}->updated('time' => $last_update, 'next' => $next);
	
	
	return $result;
}

=head2 lookup()

Lookup a URL against the Google Safe Browsing database.


Returns the list of hashes, along with the list and any metadata, that matches the URL:

  ({
	  'hash' => '...',
	  'metadata' => {
		  'malware_threat_type' => 'DISTRIBUTION'
		},
	  'list' => {
		  'threatEntryType' => 'URL',
			'threatType' => 'MALWARE',
			'platformType' => 'ANY_PLATFORM'
		},
	  'cache' => '300s'
  },
  ...
  )


Arguments

=over 4

=item lists

Optional. Lookup against pecific lists. Use the list(s) from new() by default.

=item url

Required. URL to lookup.

=back

=cut

sub lookup {
	my ($self, %args) = @_;
	my $lists					= $args{lists} || $self->{lists} || [];
	my $url 					= $args{url}		|| return ();

	my $all_lists = $self->make_lists(lists => $lists);

	# fix for http:///foo.com (3 ///)
	$url =~ s/^(https?:\/\/)\/+/$1/;

	my $uri = URI->new($url)->canonical;
	my @hashes = $self->lookup_suffix(lists => $all_lists, url => $uri);
	return @hashes;
}




=head2 get_lists()

Get all the lists from Google Safe Browsing.

  my $lists = $gsb->get_lists();

Return an array reference of all the lists:

  [
    {
      'threatEntryType' => 'URL',
      'threatType' => 'MALWARE',
      'platformType' => 'ANY_PLATFORM'
    },
    {
      'threatEntryType' => 'URL',
      'threatType' => 'MALWARE',
      'platformType' => 'WINDOWS'
    },
  ...
  ]

=cut

sub get_lists {
	my ($self, %args) = @_;
	
	my $response = $self->ua->get($self->{base} . "/threatLists?key=" . $self->{key}, 
		"Content-Type" => "application/json"
	);
	
	$self->debug($response->request->as_string);
	$self->debug($response->as_string, "\n");

	my $info = decode_json($response->content);
	return $info->{threatLists};
}



=pod

=head1 PRIVATE FUNCTIONS

These functions are not intended to be used externally.

=head2 lookup_suffix()

Lookup a host prefix.

=cut

sub lookup_suffix {
	my ($self, %args) = @_;
	my $lists 				= $args{lists} 	|| croak "Missing lists\n";
	my $url 					= $args{url}		|| return '';

	# Calculate prefixes
	my $start = time();
	my @full_hashes = $self->full_hashes($url);
	$self->perf("Full hashes from URL: ", time() - $start,  "s ");
	
 	# Local lookup
 	$start = time();
 	my @prefixes = $self->{storage}->get_prefixes(hashes => [@full_hashes], lists => $lists);
 	$self->perf("Local lookup: ", time() - $start,  "s ");
 	
	if (scalar @prefixes == 0) {
		$self->debug("No hit in local lookup\n");
		return ();
	}

	$self->debug("Found ", scalar(@prefixes), " prefix(s) in local database\n");
# 	$self->debug(Dumper(\@prefixes));
	

	# get stored full hashes
	$start = time();
	foreach my $hash (@full_hashes) {
		my @hashes = $self->{storage}->get_full_hashes(hash => $hash, lists => $lists);
		
		if (scalar @hashes > 0) {
			$self->debug("Full hashes found locally: ", scalar(@hashes), "\n");

			return (@hashes);
		}
	}
	$self->perf("Stored hashes lookup: ", time() - $start,  "s ");


	# ask for new hashes
	# TODO: make sure we don't keep asking for the same over and over
	$start = time();
	my @hashes = $self->request_full_hash(prefixes => [ @prefixes ]);
	$self->perf("Full hash request: ", time() - $start,  "s ");
	
	# Make sure the full hash match one of the full hashes for a give URL
	my @results = ();
	$start = time();
	foreach my $full_hash (@full_hashes) {
		my @matches = grep { $_->{hash} eq $full_hash } @hashes;
		push(@results, @matches) if (scalar @matches > 0);
	}
	$self->perf("Full hash check: ", time() - $start,  "s ");
	
	
	$start = time();
	$self->{storage}->add_full_hashes(hashes => [@results], timestamp => time());
	$self->perf("Save full hashes: ", time() - $start,  "s ");
	
	return @results;
}

=head2 make_lists()

Transform a list from a string ("MALWARE/*/*") into a list object.

=cut

sub make_lists {
	my ($self, %args) = @_;
	my @lists		= @{ $args{lists} || $self->{lists} || [] };
	
	if (scalar @lists == 0) {
		if (scalar @{ $self->{all_lists} } == 0) {
			$self->{all_lists} = $self->get_lists();
		}
	
		return $self->{all_lists};
	}
	
	my @all = ();
	
	foreach my $list (@lists) {
		$list = uc trim($list);
		if ($list !~ /^[*_A-Z]+\/[*_A-Z]+\/[*_A-Z]+$/) {
			$self->error("List is invalid format: $list - It must be in the form MALWARE/WINDOWS/URL or MALWARE/*/*");
			next;
		}
		if ($list =~ /\*/) {
			my ($threat, $platform, $threatEntry) = split /\//, $list;
			
			if (scalar @{ $self->{all_lists} } == 0) {
				$self->{all_lists} = $self->get_lists();
			}
			
			foreach my $original (@{ $self->{all_lists} }) {
				if (($threat eq "*" || $original->{threatType} eq $threat) &&
				    ($platform eq "*" || $original->{platformType} eq $platform) &&
				    ($threatEntry eq "*" || $original->{threatEntryType} eq $threatEntry)) {
							push(@all, $original)
				}
			}
		}
		elsif ($list =~ /^([_A-Z]+)\/([_A-Z]+)\/([_A-Z]+)$/) {
			my ($threat, $platform, $threatEntry) = split /\//, $list;
			
			push(@all, {
				threatType			=> $threat,
				platformType		=> $platform,
				threatEntryType	=> $threatEntry,
			});
		}
	}
	
	return [@all];
}


=head2 update_error()

Handle server errors during a database update.

=cut

sub update_error {
	my ($self, %args) = @_;
	my $time			= $args{'time'}	|| time;

	my $info = $self->{storage}->last_update();
	$info->{errors} = 0 if (! exists $info->{errors});
	my $errors = $info->{errors} + 1;
	my $wait = 0;

	$wait = $errors == 1 ? 60
		: $errors == 2 ? int(30 * 60 * (rand(1) + 1)) # 30-60 mins
	    : $errors == 3 ? int(60 * 60 * (rand(1) + 1)) # 60-120 mins
	    : $errors == 4 ? int(2 * 60 * 60 * (rand(1) + 1)) # 120-240 mins
	    : $errors == 5 ? int(4 * 60 * 60 * (rand(1) + 1)) # 240-480 mins
	    : $errors  > 5 ? 480 * 60
		: 0;

	$self->{storage}->update_error('time' => $time, 'wait' => $wait, errors => $errors);

}


=head2 make_lists_for_update()

Format the list objects for update requests.

=cut

sub make_lists_for_update {
	my ($self, %args) = @_;
	my @lists					= @{ $args{lists} };
	
	for(my $i = 0; $i < scalar @lists; $i++) {
		$lists[$i]->{'state'} = $self->{storage}->get_state(list => $lists[$i]);
		$lists[$i]->{constraints} = {
			supportedCompressions => ["RAW"]
		};
	}
	
	return @lists;
}

=head2 ua()

Create LWP::UserAgent to make HTTP requests to Google.

=cut

sub ua {
	my ($self, %args) = @_;

	if (! exists $self->{ua}) {
		my $ua = LWP::UserAgent->new;
  		$ua->timeout(60);
  		$ua->default_header("Content-Type" => "application/json");

		$self->{ua} = $ua;
	}

	return $self->{ua};
}


=head2 hex_to_ascii()

Transform hexadecimal strings to printable ASCII strings. Used mainly for debugging.

  print $gsb->hex_to_ascii('hex value');

=cut

sub hex_to_ascii {
	my ($self, $hex) = @_;

	return String::HexConvert::ascii_to_hex($hex);
}


=head2 ascii_to_hex()

Transform ASCII strings to hexadecimal strings.

=cut

sub ascii_to_hex {
	my ($self, $ascii) = @_;

	my $hex = '';
	for (my $i = 0; $i < int(length($ascii) / 2); $i++) {
		$hex .= chr hex( substr($ascii, $i * 2, 2) );
	}

	return $hex;
}

=head2 debug()

Print debug output.

=cut

sub debug {
	my ($self, @messages) = @_;

	print join('', @messages, "\n") if ($self->{debug} > 0);
}


=head2 error()

Print error message.

=cut

sub error {
	my ($self, @messages) = @_;

	print "ERROR - ", join('', @messages, "\n") if ($self->{debug} > 0 || $self->{errors} > 0);
	$self->{last_error} = join('', @messages);
}


=head2 perf()

Print performance message.

=cut

sub perf {
	my ($self, @messages) = @_;

	print join('', @messages, "\n") if ($self->{perf} > 0);
}


=head2 canonical_domain()

Find all canonical domains a domain.

=cut

sub canonical_domain {
	my ($self, $domain) 	= @_;

	# Remove all leading and trailing dots.
  $domain =~ s/^\.+//;
  $domain =~ s/\.+$//;

	# Replace consecutive dots with a single dot.
	while ($domain =~ s/\.\.+/\./g) { }

	# Lowercase the whole string.
	$domain = lc $domain;

	my @domains = ($domain);


	if ($domain =~ /^\d+\.\d+\.\d+\.\d+$/) { # loose check for IP address, should be enough
		return @domains;
	} 

	my @parts = split/\./, $domain;
	splice(@parts, 0, -6); # take 5 top most compoments


	while (scalar @parts > 2) {
		shift @parts;
		push(@domains, join(".", @parts) );
	}

	return @domains;
}

=head2 canonical_path()

Find all canonical paths for a URL.

=cut

sub canonical_path {
	my ($self, $path) 	= @_;

	my @paths = ($path); # return full path
	
	# without query string
	if ($path =~ /\?/) {
		$path =~ s/\?.*$//;

		push(@paths, $path);
	}

	my @parts = split /\//, $path;
	if (scalar @parts > 4) {
		@parts = splice(@parts, -4, 4);
	}

# 	if (scalar @parts == 0) {
# 		push(@paths, "/");
# 	}


	my $previous = '';
	while (scalar @parts > 1) {
		my $val = shift(@parts);
		$previous .= "$val/";

		push(@paths, $previous);
	}
	
	return @paths;
}

=head2 canonical()

Find all canonical URLs for a URL.

=cut

sub canonical {
	my ($self, $url) = @_;

	my @urls = ();

# 	my $uri = URI->new($url)->canonical;
	my $uri = $self->canonical_uri($url);
	my @domains = $self->canonical_domain($uri->host);
	my @paths = $self->canonical_path($uri->path_query);

	foreach my $domain (@domains) {
		foreach my $path (@paths) {
			push(@urls, "$domain$path");
		}
	}

	return @urls;
}


=head2 canonical_uri()

Create a canonical URI.

NOTE: URI cannot handle all the test cases provided by Google. This method is a hack to pass most of the test. A few tests are still failing. The proper way to handle URL canonicalization according to Google would be to create a new module to handle URLs. However, I believe most real-life cases are handled correctly by this function.

=cut

sub canonical_uri {
	my ($self, $url) = @_;

	$url = trim $url;

	# Special case for \t \r \n
	while ($url =~ s/^([^?]+)[\r\t\n]/$1/sgi) { } 

	my $uri = URI->new($url)->canonical; # does not deal with directory traversing

# 	$self->debug("0. $url => " . $uri->as_string . "\n");

	
	if (! $uri->scheme() || $uri->scheme() eq '') {
		$uri = URI->new("http://$url")->canonical;
	}

	$uri->fragment('');

	my $escape = $uri->as_string;

	# Reduce double // to single / in path
	while ($escape =~ s/^([a-z]+:\/\/[^?]+)\/\//$1\//sgi) { }


	# Remove empty fragment
	$escape =~ s/#$//;

	# canonial does not handle ../ 
# 	$self->debug("\t$escape\n");
	while($escape =~ s/([^\/])\/([^\/]+)\/\.\.([\/?].*)$/$1$3/gi) {  }
	while($escape =~ s/([^\/])\/([^\/]+)\/\.\.$/$1/gi) {  }

	# May have removed ending /
# 	$self->debug("\t$escape\n");
	$escape .= "/" if ($escape =~ /^[a-z]+:\/\/[^\/\?]+$/);
	$escape =~ s/^([a-z]+:\/\/[^\/]+)(\?.*)$/$1\/$2/gi;
# 	$self->debug("\t$escape\n");

	# other weird case if domain = digits only, try to translate it to IP address
	if ((my $domain = URI->new($escape)->host) =~/^\d+$/) {
		my $ip = Socket::inet_ntoa(Socket::inet_aton($domain));

		$uri = URI->new($escape);
		$uri->host($ip);

		$escape = $uri->as_string;
	}

# 	$self->debug("1. $url => $escape\n");

	# Try to escape the path again
	$url = $escape;
	while (($escape = URI::Escape::uri_unescape($url)) ne $escape) { # wrong for %23 -> #
		$url = $escape;
	}
# 	while (($escape = URI->new($url)->canonical->as_string) ne $escape) { # breask more unit tests than previous
# 		$url = $escape;
# 	}

	# Fix for %23 -> #
	while($escape =~ s/#/%23/sgi) { }

# 	$self->debug("2. $url => $escape\n");

	# Fix over escaping
	while($escape =~ s/^([^?]+)%%(%.*)$/$1%25%25$2/sgi) { }
	while($escape =~ s/^([^?]+)%%/$1%25%25/sgi) { }

	# URI has issues with % in domains, it gets the host wrong

		# 1. fix the host
# 	$self->debug("Domain: " . URI->new($escape)->host . "\n");
	my $exception = 0;
	while ($escape =~ /^[a-z]+:\/\/[^\/]*([^a-z0-9%_.-\/:])[^\/]*(\/.*)$/) {
		my $source = $1;
		my $target = sprintf("%02x", ord($source));

		$escape =~ s/^([a-z]+:\/\/[^\/]*)\Q$source\E/$1%\Q$target\E/;

		$exception = 1;
	}

		# 2. need to parse the path again
	if ($exception && $escape =~ /^[a-z]+:\/\/[^\/]+\/(.+)/) {
		my $source = $1;
		my $target = URI::Escape::uri_unescape($source);

# 		print "Source: $source\n";
		while ($target ne URI::Escape::uri_unescape($target)) {
			$target = URI::Escape::uri_unescape($target);
		}

		
		$escape =~ s/\/\Q$source\E/\/$target/;

		while ($escape =~ s/#/%23/sgi) { } # fragement has been removed earlier
		while ($escape =~ s/^([a-z]+:\/\/[^\/]+\/.*)%5e/$1\&/sgi) { } # not in the host name
# 		while ($escape =~ s/%5e/&/sgi) { } 

		while ($escape =~ s/%([^0-9a-f]|.[^0-9a-f])/%25$1/sgi) { }
	}

# 	$self->debug("$url => $escape\n");
# 	$self->debug(URI->new($escape)->as_string . "\n");

	return URI->new($escape);
}

=head2 full_hashes()

Return all possible full hashes for a URL.

=cut

sub full_hashes {
	my ($self, $url) = @_;

	my @urls = $self->canonical($url);
	my @hashes = ();

	foreach my $url (@urls) {
# 		$self->debug("$url\n");
		push(@hashes, sha256($url));
		$self->debug("$url " . $self->hex_to_ascii(sha256($url)) . "\n");
	}

	return @hashes;
}

=head2 request_full_hash()

Request full full hashes for specific prefixes from Google.

=cut

sub request_full_hash {
	my ($self, %args) = @_;
	my @prefixes			= @{ $args{prefixes} || [] };
		
	my $info = {
		client => {
			clientId => 'Net::Google::SafeBrowsing4',
			clientVersion	=> $VERSION
		},
	};
	
	my @lists = ();
	my %hashes = ();
	my %threats = ();
	my %platforms = ();
	my %threatEntries = ();
	foreach my $info (@prefixes) {
		push(@lists, $info->{list}) if (! defined first { $_->{threatType} eq $info->{list}->{threatType} && $_->{platformType} eq $info->{list}->{platformType} && $_->{threatEntryType} eq $info->{list}->{threatEntryType} } @lists);
		$hashes{ trim encode_base64 $info->{prefix} } = 1;
		
		$threats{ $info->{list}->{threatType} } = 1;
		$platforms{ $info->{list}->{platformType} } = 1;
		$threatEntries{ $info->{list}->{threatEntryType} } = 1;
	}
	
	# get state for each list
	$info->{clientStates} = [];
	foreach my $list (@lists) {
# 		$self->debug(Dumper $list);
		push(@{ $info->{clientStates} }, $self->{storage}->get_state(list => $list));
		
	}
	
	$info->{threatInfo} = {
		threatTypes				=> [keys %threats],
		platformTypes 		=> [keys %platforms],
		threatEntryTypes 	=> [keys %threatEntries],
		threatEntries			=> [
			map { {hash => $_ } } keys %hashes,
		],
	};
	
	my $response = $self->ua->post($self->{base} . "/fullHashes:find?key=" . $self->{key}, 
		"Content-Type" => "application/json",
		Content => encode_json($info)
	);
	
	$self->debug($response->request->as_string);
	$self->debug($response->as_string, "\n");
	
	if (! $response->is_success) {
		$self->error("Full hash request failed\n");
	
		# TODO
# 		foreach my $info (keys keys %hashes) {
# 			my $prefix = $info->{prefix};
# 	
# 			my $errors = $self->{storage}->get_full_hash_error(prefix => $prefix);
# 			if (defined $errors && (
# 				$errors->{errors} >=2 			# backoff mode
# 				|| $errors->{errors} == 1 && (time() - $errors->{timestamp}) > 5 * 60)) { # 5 minutes
# 					$self->{storage}->full_hash_error(prefix => $prefix, timestamp => time()); # more complicate than this, need to check time between 2 errors
# 			}
# 		}

		return ();
	}
	else {
		$self->debug("Full hash request OK\n");

		# TODO
# 		foreach my $prefix (@$prefixes) {
# 			my $prefix = $info->{prefix};
# 		
# 			$self->{storage}->full_hash_ok(prefix => $prefix, timestamp => time());
# 		}
	}

	return $self->parse_full_hashes($response->content);
}

=head2 parse_full_hashes()

Process the request for full hashes from Google.

=cut

sub parse_full_hashes {
	my ($self, $data) 	= @_;

	if ($data eq '') {
		return ();
	}
	
	
	
	my $info = decode_json($data);
	if (! exists $info->{matches} || scalar @{ $info->{matches} } == 0) {
		return ();
	}

	my @hashes = ();
	foreach my $match (@{ $info->{matches} }) {
		my $list = {
			threatType			=> $match->{threatType},
			platformType		=> $match->{platformType},
			threatEntryType	=> $match->{threatEntryType},
		};
		
		my $hash = decode_base64($match->{threat}->{hash});
		my $cache = $match->{cacheDuration};
		
		my %metadata = ();
		foreach my $extra (@{ $match->{threatEntryMetadata}->{entries} }) {
			$metadata{ decode_base64 $extra->{key} } = decode_base64 $extra->{value};
		}
		
		push(@hashes, { hash => $hash, cache => $cache, list => $list, metadata => { %metadata } });
	}
	
	# TODO:	
	my $wait = $info->{minimumWaitDuration} || 0; # "300.000s",
	$wait =~ s/[a-z]//i;
	
  my $negativeWait = $info->{negativeCacheDuration} || 0; #"300.000s"
	$negativeWait =~ s/[a-z]//i;
	
	return @hashes;
}



=head1 SEE ALSO

See L<Net::Google::SafeBrowsing4> for handling Google Safe Browsing v4.

See L<Net::Google::SafeBrowsing4::Storage> for the list of public functions.

See L<Net::Google::SafeBrowsing4::File> for a back-end storage using files.

Google Safe Browsing v4 API: L<https://developers.google.com/safe-browsing/v4/>


=head1 AUTHOR

Julien Sobrier, E<lt>julien@sobrier.netE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2016 by Julien Sobrier

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut

1;
__END__

