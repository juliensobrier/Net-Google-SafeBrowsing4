#!perl

# ABSTRACT: URI Normalization tests for Net::Google::SafeBrowsing4::URI class

use strict;
use warnings;

use Test::More 0.92 qw(no_plan);

use Net::Google::SafeBrowsing4::URI;


my @invalid_uris = (
	# Empty, null host is not valid
	undef,
	'',
	# Only http and https scheme is supported by Googe::SafeBrowsing4 x2
	'mailto:my@email.site',
	"shihtzu://google.com",
	"http://:80/index.html",
);

my %uris = (
	# Doesn't destroy a simple, properly formatted uri:
	'http://google.com/' => 'http://google.com/',
	# Adds trailing slash to a simple domain with no path
	'http://google.com' => 'http://google.com/',
	# Works with https too
	'https://google.com/' => 'https://google.com/',
	# Mixed-cased scheme get lowercsed
	'HTTp://google.com/' => 'http://google.com/',
	# mixed case host/domain get lowercased
	'http://Google.COM/' => 'http://google.com/',
	# Triple or more slash get normalized x2
	'http:///google.com/' => 'http://google.com/',
	'http://////google.com/' => 'http://google.com/',
	# Leading and Trailing Whitespaces get removed x2
	'  http://google.com/   ' => 'http://google.com/',
	"\n\r\t http://google.com/\n\r\t   " => 'http://google.com/',
	# Default port get removed x2
	'http://google.com:80/' => 'http://google.com/',
	'https://google.com:443/' => 'https://google.com/',
	# Non-default port get removed
	'http://google.com:8080/' => 'http://google.com/',
	# URI without scheme
	"google.com" => 'http://google.com/',
	# URI with tab/CR/LF characters in it x3
	"http://google\n.com/" => 'http://google.com/',
	"http://google\n.com/in\t/the\r/path" => 'http://google.com/in/the/path',
	"http://google.com/?query=\r\n&param=\tdata" => 'http://google.com/?query=&param=data',
	# Remove Fragment
	'http://google.com/#fragment' => 'http://google.com/',
	'http://google.com/#frag#frag' => 'http://google.com/',
	'http://google.com/path/index.html##frag' => 'http://google.com/path/index.html',
	# Percent un-escape
	'http://google%2ecom/path/index%25252525252ehtml' => 'http://google.com/path/index.html',
	'http://google.com/path/index.html?data=%81%80%0f' => 'http://google.com/path/index.html?data=%81%80%0F',
	# Leading/Trailing/Consecutive dots in hostname
	'http://...google...com.../' => 'http://google.com/',
	'http://google.com./' => 'http://google.com/',
	'http://.google..com./' => 'http://google.com/',
	# Remove username
	'http://username@google.com/' => 'http://google.com/',
	# Remove username-password pair
	'http://username:passworten@google.com/' => 'http://google.com/',
	# Normalization works on email-looking HTTP address
	'username@google.com' => 'http://google.com/',
	# Removes username even with more @ marks
	'http://user@@name@google.com/' => 'http://google.com/',
);

foreach my $uri (sort { ($a || '') cmp ($b || '') } @invalid_uris) {
	my $gsb_uri = Net::Google::SafeBrowsing4::URI->new($uri);
	is($gsb_uri, undef, "Invalid URI '". ($uri || "(undef)") ."'  detected");
}

foreach my $uri (sort(keys(%uris))) {
	my $gsb_uri = Net::Google::SafeBrowsing4::URI->new($uri);
	ok($gsb_uri, "URI parsed: ". $uri);
	is($gsb_uri->as_string(), $uris{$uri}, "Normalize URI '". $uri ."'  to '". $uris{$uri} ."' (got: '". $gsb_uri->as_string() ."')");
}
