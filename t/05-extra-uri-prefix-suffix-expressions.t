#!perl

use strict;
use warnings;

use Test::More qw(no_plan);

use Net::Google::SafeBrowsing4;


my %urls = (
	'http://www1.rapidsoftclearon.net/' =>  { map { $_ => 1 } qw(
		www1.rapidsoftclearon.net/
		rapidsoftclearon.net/
	)},
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
