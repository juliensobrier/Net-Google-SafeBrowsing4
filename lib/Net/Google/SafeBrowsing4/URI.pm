package Net::Google::SafeBrowsing4::URI;

use strict;
use warnings;

use Net::IP::Lite qw();
use Socket qw(inet_ntoa);
use URI;

=head1 NAME

Net::Google::SafeBrowsing4::URI - Class for URI management for the Google::SafeBrowsing (version 4) API.


=head1 SYNOPSIS

	use Net::Google::SafeBrowsing4::URI;

	my $gsb_uri = Net::Google::SafeBrowsing4::URI->new('http://my.example.site:80/path/to/file.html?query=param#fraction');
	my @uris = $gsb_uri->canonicalize();

=head1 DESCRIPTION

Net::Google::SafeBrowsing4::URI takes care of normalizing URLs, extracting suffix/prefix expressions, calculating hashes.

=head1 METHODS

=item new

	my $gsb_uri = Net::Google::SafeBrowsing4::URI->new('http://my.example.site:80/path/to/file.html?query=param#fraction');

=over

Initializes the object.

Arguments:

=item $uri The URL to parse

=back

=cut

sub new {
	my $class = shift;
	my @args = @_;

	if (scalar(@args) == 0) {
		die("Missing parameters: URI");
	}

	my $self = {
		rawuri => $args[0],
	};

	bless($self, $class) or croak("Can't bless $class: $!");

	return $self->_normalize() ? $self : undef;
}

=item as_string

=over

Returns the normalized URI as string.

=back

=cut

sub as_string {
	my $self = shift;

	return $self->{uri};
}

=head1 PRIVATE METHODS

=item _normalize

=over

Parses and normalizes the URI.

=back

=cut

sub _normalize {
	my $self = shift;
	my $modified_rawuri = $self->{rawuri};

	# Remove third and more slashes after the scheme
	$modified_rawuri =~ s/^(\s*https?:\/\/)\/+/$1/si;
	# Remove any Tab, CR, LF characters from the URI
	$modified_rawuri =~ s/[\r\n\t]+//sgi;
	# Recursive percent-unescape (everything but '#' not to confuse URI parser)
	while ($modified_rawuri =~ s{%(?!23)([[:xdigit:]]{2})}{chr(hex($1))}esg) { }

	# Parse URI
	my $uri_obj = URI->new($modified_rawuri);
	if (ref($uri_obj) !~ /^URI::https?$/ && !$uri_obj->scheme()) {
		$uri_obj = URI->new("http://" . $modified_rawuri);
	}
	# Only http and https URIs are supported
	if (ref($uri_obj) !~ /^URI::https?$/) {
		return undef;
	}

	# Remove userinfo
	$uri_obj->userinfo(undef);
	# Remove port
	$uri_obj->port(undef);
	# Remove Fragment
	$uri_obj->fragment(undef);

	# Host modifications
	my $modified_host = $uri_obj->host();
	# Host part cannot be empty
	if ($modified_host =~ /^\s*$/) {
		return undef;
	}
	# Collapse consecutive dots into one
	$modified_host =~ s/\.\.+/\./sg;
	# Remove leading and trailing dot
	$modified_host =~ s/^\.|\.$//sg;

	# IPv4 canonicalizations
	$modified_host = _normalize_ip($modified_host);
	if (!defined($modified_host)) {
		return undef;
	}
	$uri_obj->host($modified_host);

	my $modified_path = $uri_obj->path();
	# Eliminate current directory /./ parts
	$modified_path =~ s/\/\.(?:\/|$)/\//sg;
	# Eliminate parent directory /something/./ parts
	$modified_path =~ s/\/[^\/]+\/\.\.(?:\/|$)/\//sg;
	# Eliminate double // slashes from path
	$modified_path =~ s/\/\/+/\//sg;
	$uri_obj->path($modified_path);

	# Fix some percent encoding
	my $modified_path_query = $uri_obj->path_query();
	# Fix lone percent signs %
	$modified_path_query =~ s/%(?![[:xdigit:]]{2})/%25/sg;
	$uri_obj->path_query($modified_path_query);

	my $canonical = $uri_obj->canonical();
	# Fix caret escaping
	$canonical=~ s/%5E/\^/sg;

	$self->{uri} = $canonical;

	return $self->{uri};
}

=head1 PRIVATE FUNCTIONS

=item _normalize_ip

=over

Function for recognising various IPv4 formatted addresses and convert them to I<dotted-decimal-quad> format (111.11.1.1)

=back

=cut

sub _normalize_ip {
	my $host = shift;

	# Shortcut: If it doesn't look like an IPv4, then return early
	if ($host !~ /^[[:xdigit:]x\.]+$/) {
		return $host;
	}

	# Most formats are detected and converted by Net::IP::Lite
	my $ip = Net::IP::Lite->new($host);
	if ($ip) {
		return $ip->transform();
	}

	# One and two dots case is missing: xxx.xxxxxxxxxx, xxx.xxx.xxxxxx
	my $bits = 32;
	my @segments = split(/\./, $host);
	my $segment_count = scalar(@segments);

	my $decimal = 0;
	for (my $i = 0; $i < $segment_count; $i++) {
		my $is_last_segment = $i >= $segment_count - 1;
		my $segment = _parse_ipv4_segment($segments[$i], !$is_last_segment ? 8 : $bits);
		if (!defined($segment)) {
			return undef;
		}
		$bits -= 8;
		$decimal +=  $segment << (!$is_last_segment ? $bits : 0);
	}

	$ip = Net::IP::Lite->new($decimal);
	if ($ip) {
		return $ip->transform();
	}

	return $host;
}

=item _parse_ipv4_segment

	my $decimal = _parse_ipv4_part($segment, $bits)

=over

Transforms one IPv4 segment to decimal with range checking.

Arguments:

=item $segment

Decimal/octal/hexadecimal value to parse

=item $bits

Bit length for range checking

=cut

sub _parse_ipv4_segment {
	my $segment = shift;
	my $bits = shift;
	my $decimal;

	if ($segment =~ /^0+([0-7]+)$/) {
		$decimal = oct($1);
	}
	elsif ($segment =~ /^0x0*([[:xdigit:]]+)$/) {
		$decimal = hex($1);
	}
	elsif ($segment =~ /^[1-9]\d+$/) {
		$decimal = $segment;
	}
	else {
		return undef;
	}

	if ($decimal >= (1 << $bits)) {
		return undef;
	}
	return $decimal;
}

=head1 BUGS

Some URI normalizatuion cases are still missing:

=item Caret (^) is turned into %5E.

=item Highbit characters in hostname are punycoded, not percent encoded.

I<This should be the right case, but Google's tests suggest otherwise - need to confirm.>

=head1 AUTHORS

Julien Sobrier, E<lt>julien@sobrier.netE<gt>,
Tamás Fehérvári, E<lt>geever@users.sourceforge.net<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2016 by Julien Sobrier

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
