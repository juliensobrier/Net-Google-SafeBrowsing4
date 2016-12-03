#!perl

use strict;
use warnings;

use Test::More qw(no_plan);

use Net::Google::SafeBrowsing4::URI;


# Extra URI Canonicalization tests
my %uris = (
	'http://www.google.com/a/../b/../c' => 'http://www.google.com/c',
	'http://www.google.com/a/../b/..' => 'http://www.google.com/',
	'http://www.google.com/a/../b/..?foo' => 'http://www.google.com/?foo',
	'http://www.google.com/#a#b' => 'http://www.google.com/',
	'http://www.google.com/#a#b#c' => 'http://www.google.com/',
	'http://16843009/index.html' => 'http://1.1.1.1/index.html',
	'http://1/index.html' => 'http://0.0.0.1/index.html'
);

foreach my $uri (sort(keys(%uris))) {
	my $gsb_uri = Net::Google::SafeBrowsing4::URI->new($uri);
	ok($gsb_uri, "URI parsed: ". $uri);
	is($gsb_uri->as_string(), $uris{$uri}, "Normalize URI '". $uri ."'  to '". $uris{$uri} ."' (got: '". $gsb_uri->as_string() ."')");
}
