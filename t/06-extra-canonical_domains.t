#!perl

use strict;
use warnings;

use Test::More qw(no_plan);

use Net::Google::SafeBrowsing4;


my %urls = (
	'foo...com' =>  { map { $_ => 1 } qw(
		foo.com
	)},
	'FoO..com' =>  { map { $_ => 1 } qw(
		foo.com
	)},
	'foo.com...' =>  { map { $_ => 1 } qw(
		foo.com
	)},
	'...foo.com' =>  { map { $_ => 1 } qw(
		foo.com
	)},
	'www.google.com' =>  { map { $_ => 1 } qw(
		www.google.com
		google.com
	)},
	'google.com' =>  { map { $_ => 1 } qw(
		google.com
	)},
	'malware.testing.google.test' =>  { map { $_ => 1 } qw(
		malware.testing.google.test
		testing.google.test
		google.test
	)}
);


my $gsb = Net::Google::SafeBrowsing4->new();

foreach my $url (keys(%urls)) {
	my @expressions = $gsb->canonical_domain($url);
	is(scalar(@expressions), scalar(keys(%{$urls{$url}})), "Number of possible prefix/suffix expressions for '". $url ."'");
	foreach my $expression (@expressions) {
		ok(exists($urls{$url}->{$expression}), "prefix/suffix expression '". $expression ."' found");
		delete($urls{$url}->{$expression});
	}
	is(scalar(keys(%{$urls{$url}})), 0, "All prefix/suffix expressions found");
}
