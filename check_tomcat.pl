#!/usr/bin/perl

#
# Generic Nagios JSESSIONID check for Tomcat
#
# Allows for a generic check between two requests to the given host and does
# comparisons within each request to verify the JSESSIONID cookie string is
# the same in the header and body content and different between each request
#

use warnings;
use strict;
use LWP;
use Getopt::Long;
use Data::Dumper;

$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

my ($scheme, $hostname, $port, $path, $response1, $response2, $secure, $help, $debug, $ua, $headjsid1, $bodyjsid1, $headjsid2, $bodyjsid2, $jsid1ok, $jsid2ok, @jsid1, @jsid2);

sub usage() {
  print "Unknown option: @_\n" if ( @_ );
  print "${0} - Generic Nagios check for Tomcat\nUsage: ${0} --hostname <fqdn> --path <path> [--port <port>][--secure][--debug][--help|-?]\n";
  exit 3; # Changed from '1' to '3' for Nagios state Unknown -- Stefan 2013-04-26
}

usage() if(@ARGV < 1 or ! GetOptions('hostname=s' => \$hostname, 'path=s' => \$path, 'port:s' => \$port, 'secure' => \$secure, 'help|?' => \$help, 'debug' => \$debug) or defined $help or ! defined $hostname or ! defined $path);

if(defined $port) {
  $port = ':' . $port;
} else {
  $port = '';
}

if(defined $secure) {
  $scheme = 'https://';
} else {
  $scheme = 'http://';
}

sub uniq {
  return keys %{{ map { $_ => 1 } @_ }};
}

$ua = LWP::UserAgent->new;
$response1 = $ua->get("${scheme}${hostname}${port}${path}");
unless ( $response1->is_success ) {
  print "Could not get '${scheme}${hostname}${port}${path}' -- " . $response1->status_line . "\n" ;
  exit 2 ;
}
$response2 = $ua->get("${scheme}${hostname}${port}${path}");

if(defined $debug) { print Dumper($response1,$response2); }

if($response1->headers()->as_string =~ /.*JSESSIONID=([\w\d]+)\;/) {
  $headjsid1 = $1;
  if(defined $debug) { print "First attempt header JSESSIONID string: $headjsid1\n"; }
} else {
  print "Tomcat JSESSIONID not found in first attempt to ${scheme}${hostname}${port}${path} header content\n";
  exit 2; 
}

if($response1->content =~ /.*jsessionid=([\w\d]{32})/) {
  $bodyjsid1 = $1;
  if(defined $debug) { print "First attempt body JSESSIONID string: $bodyjsid1\n"; }
} else {
  print "Tomcat JSESSIONID not found in first attempt to ${scheme}${hostname}${port}${path} body content\n";
  exit 2;
}

if($response2->headers()->as_string =~ /.*JSESSIONID=([\w\d]+)\;/) {
  $headjsid2 = $1;
  if(defined $debug) { print "Second attempt header JSESSIONID string: $headjsid2\n"; }
} else {
  print "Tomcat JSESSIONID not found in second attempt to ${scheme}${hostname}${port}${path} header content\n";
  exit 2;
}

if($response2->content =~ /.*jsessionid=([\w\d]{32})/) {
  $bodyjsid2 = $1;
  if(defined $debug) { print "Second attempt body JSESSIONID string: $bodyjsid2\n"; }
} else {
  print "Tomcat JSESSIONID not found in second attempt to ${scheme}${hostname}${port}${path} body content\n";
  exit 2;
}

if($headjsid1 eq $bodyjsid1) {
  push(@jsid1,$headjsid1,$bodyjsid1);
  $jsid1ok = join(" ", uniq(@jsid1));
} else {
  print "Tomcat JSESSIONID not unique between header and body content on first attempt to ${scheme}${hostname}${port}${path}: head:${headjsid1} body:${bodyjsid1}\n";
  exit 2;
}

if($headjsid2 eq $bodyjsid2) {
  push(@jsid2,$headjsid2,$bodyjsid2);
  $jsid2ok = join(" ", uniq(@jsid2));
} else {
  print "Tomcat JSESSIONID not unique between header and body content on second attempt to ${scheme}${hostname}${port}${path}: head:${headjsid2} body:${bodyjsid2}\n";
  exit 2;
}

if($jsid1ok ne $jsid2ok) {
  print "Tomcat JSESSIONID OK on both attempts to ${scheme}${hostname}${port}${path}: first:${jsid1ok} second:${jsid2ok}\n";
  exit 0;
} else {
  print "Tomcat JSESSIONID problem between both attempts to ${scheme}${hostname}${port}${path}: first:${jsid1ok} second:${jsid2ok}\n";
  exit 2;
}

print "An unhandled condition was detected by ${0}\n" ;
exit 3 ;
