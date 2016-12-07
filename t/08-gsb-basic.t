#!/usr/bin/perl

# ABSTRACT: Basic tests about the Net::Google::SafeBrowsing4 class

use strict;
use warnings;

use Test::More qw(no_plan);

use Net::Google::SafeBrowsing4::File;

BEGIN {
	use_ok("Net::Google::SafeBrowsing4");
};

require_ok("Net::Google::SafeBrowsing4");

my $gsb;
$gsb = Net::Google::SafeBrowsing4->new();
is($gsb, undef, "SafeBrowsing4 obejct needs an API key.");

$gsb =  new_ok(
	"Net::Google::SafeBrowsing4" => [
		key => "random-api-key-random-api-key-random-ap",
	],
	"Net::Google::SafeBrowsing4"
);

$gsb = Net::Google::SafeBrowsing4->new(
	key => "random-api-key-random-api-key-random-ap",
	storage => Net::Google::SafeBrowsing4::File->new(path => "."),
);
# Check User Agent
ok($gsb->{http_agent}, "SafeBrowsing object got an LWP object");
