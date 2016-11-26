#!perl

use strict;
use warnings;

use Test::More qw(no_plan);

use Net::Google::SafeBrowsing4;


# Extra URI Canonicalization tests
my %urls = (
	'http://www.google.com/a/../b/../c' => 'http://www.google.com/c',
	'http://www.google.com/a/../b/..' => 'http://www.google.com/',
	'http://www.google.com/a/../b/..?foo' => 'http://www.google.com/?foo',
	'http://www.google.com/#a#b' => 'http://www.google.com/',
	'http://www.google.com/#a#b#c' => 'http://www.google.com/',
	'http://16843009/index.html' => 'http://1.1.1.1/index.html',
	'http://1/index.html' => 'http://0.0.0.1/index.html'
);


my $gsb = Net::Google::SafeBrowsing4->new();

foreach my $uri (keys(%urls)) {
	is( $gsb->canonical_uri($uri), $urls{$uri}, "Canonicalization of URI '". $uri ."'");
}
