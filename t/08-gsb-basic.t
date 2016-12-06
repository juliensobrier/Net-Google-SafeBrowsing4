#!/usr/bin/perl

# ABSTRACT: Basic tests about the Net::Google::SafeBrowsing4 class

use strict;
use warnings;

use Test::More qw(no_plan);

BEGIN {
	use_ok('Net::Google::SafeBrowsing4');
};

require_ok('Net::Google::SafeBrowsing4');

my $gsb = new_ok('Net::Google::SafeBrowsing4' => [], 'Net::Google::SafeBrowsing4');
