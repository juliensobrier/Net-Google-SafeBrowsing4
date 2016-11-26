#!perl

use strict;
use warnings;

use Test::More qw(no_plan);

use Net::Google::SafeBrowsing4;


# URI suffix/prefix expressions extraction tests from Google's API webpage:
# https://developers.google.com/safe-browsing/v4/urls-hashing#suffixprefix-expressions
my %urls = (
	'http://a.b.c/1/2.html?param=1' => { map { $_ => 1 } qw(
		a.b.c/1/2.html?param=1
		a.b.c/1/2.html
		a.b.c/
		a.b.c/1/
		b.c/1/2.html?param=1
		b.c/1/2.html
		b.c/
		b.c/1/
	)},
	'http://a.b.c.d.e.f.g/1.html' => { map { $_ => 1 } qw(
		a.b.c.d.e.f.g/1.html
		a.b.c.d.e.f.g/
		c.d.e.f.g/1.html
		c.d.e.f.g/
		d.e.f.g/1.html
		d.e.f.g/
		e.f.g/1.html
		e.f.g/
		f.g/1.html
		f.g/
	)},
	'http://1.2.3.4/1/' => { map { $_ => 1 } qw(
		1.2.3.4/1/
		1.2.3.4/
	)}
);

my $gsb = Net::Google::SafeBrowsing4->new();

foreach my $url (keys(%urls)) {
	my @expressions = $gsb->canonical($url);
	is(scalar(@expressions), scalar(keys(%{$urls{$url}})), "Number of possible prefix/suffix expressions for '". $url ."'");
	foreach my $expression (@expressions) {
		ok(exists($urls{$url}->{$expression}), "prefix/suffix expression '". $expression ."' found");
		delete($urls{$url}->{$expression});
	}
	is(scalar(keys(%{$urls{$url}})), 0, "All prefix/suffix expressions found");
}
