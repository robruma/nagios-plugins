#!/usr/bin/perl

#
# Generic Nagios check for blacklist monitoring --robruma
#
# Checks an IPv4 address for the presence of an A record and TXT record on well known dnsbl zones. 
# Returns a Nagios OK, alert or warning depending on the status and which array the dnsbl zone is on.
#

use strict;
use warnings;
use Getopt::Long;
use Net::DNS;
use Data::Dumper;

$ENV{'PATH'} = '/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin';

my ($debug, $help, $ip, $ptr, $res, $querya, $querytxt, $rr, $bl, $blkey, $blvalue, @dnsblalert, @dnsblwarn, @dnsblall, @exitchk, $entry, $alert, %answer);
my $exit = 0;

sub usage() {
  print "Unknown option: @_\n" if ( @_ );
  print "${0} - Generic Nagios check for blacklist monitoring\nUsage: ${0} --ip ip [--dnsbl zone[,zone,...]][--debug][--help|-?]\n";
  exit 3;
}

usage() if(@ARGV < 1 or ! GetOptions('ip=s' => \$ip, 'dnsbl=s' => \@dnsblall, 'help|?' => \$help, 'debug' => \$debug) or ! defined $ip or defined $help);

usage() if($ip !~ /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/) and print "IP regex error\n";

# dnsbl zones we only want to warn about
@dnsblwarn = ("ips.backscatterer.org", "st.technovision.dk", "ip.v4bl.org");

if(defined $debug and @dnsblall) { print "Override dnsbl zone list: @dnsblall\n\n"; }
if(defined $debug and ! @dnsblall) { print "Warning dnsbl zone list: @dnsblwarn\n\n"; }

# dnsbl zones we want to alert for
@dnsblalert = ("0spam.fusionzero.com", "access.redhawk.org", "all.rbl.jp", "all.s5h.net", "all.spamrats.com", "b.barracudacentral.org", "bl.blocklist.de", "bl.emailbasura.org", "bl.mailspike.org", "bl.score.senderscore.com", "bl.spamcannibal.org", "bl.spamcop.net", "bl.spameatingmonkey.net", "bogons.cymru.com", "cblplus.anti-spam.org.cn", "cidr.bl.mcafee.com", "combined.njabl.org", "db.wpbl.info", "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net", "dnsbl.ahbl.org", "dnsbl.burnt-tech.com", "dnsbl.dronebl.org", "dnsbl.inps.de", "dnsbl.justspam.org", "dnsbl.kempt.net", "dnsbl.rv-soft.info", "dnsbl.sorbs.net", "dnsbl.webequipped.com", "dnsrbl.swinog.ch", "fnrbl.fast.net", "ix.dnsbl.manitu.net", "korea.services.net", "l2.apews.org", "l2.bbfh.ext.sorbs.net", "list.blogspambl.com", "lookup.dnsbl.iip.lu", "mail-abuse.blacklist.jippg.org", "psbl.surriel.com", "rbl2.triumf.ca", "rbl.choon.net", "rbl.dns-servicios.com", "rbl.efnetrbl.org", "rbl.orbitrbl.com", "rbl.polarcomm.net", "singlebl.spamgrouper.com", "spam.abuse.ch", "spam.dnsbl.sorbs.net", "spam.pedantic.org", "spamguard.leadmon.net", "spamrbl.imp.ch", "spamsources.fabel.dk", "spamtrap.trblspam.com", "tor.dan.me.uk", "tor.dnsbl.sectoor.de", "truncate.gbudb.net", "ubl.unsubscore.com", "virbl.dnsbl.bit.nl", "work.drbl.gremlin.ru", "zen.spamhaus.org");

if(defined $debug and ! @dnsblall) { print "Alert dnsbl zone list: @dnsblalert\n\n"; }

# Logic to override the dnsbl zone list
if(@dnsblall) {
  @dnsblall = split(/,/,join(',',@dnsblall));
} else {
  @dnsblall = (@dnsblwarn,@dnsblalert);
}

# Iterate through all dnsbl zones and check our IP
foreach $bl (@dnsblall) {
  if(defined $debug) { print "Checking $bl for $ip\n"; }
  $ptr = join('.', reverse split(/\./, $ip)).".${bl}";
  $res = Net::DNS::Resolver->new;
  $res->udp_timeout(1);
  $querya = $res->query($ptr,'A');
  $querytxt = $res->query($ptr,'TXT');
  if(defined $debug) { if(defined $res->errorstring) { print "Query error string: " . $res->errorstring . "\n\n"; }}

  # DNS A record query 
  if ($querya) {
    foreach my $rr ($querya->answer) {
      next unless $rr->type eq "A";
      if(defined $debug) { print "*** Found $ip in $bl zone\n"; }
      if(defined $debug) { print "*** Record type: " . $rr->type . "\n"; }
      if ($rr->type eq "A") {
        $answer{$bl}->{code} = $rr->rdatastr;
        if(defined $debug) { print "*** Code $answer{$bl}->{code}\n\n"; }
      }
    }
  }

  # DNS TXT record query 
  if ($querytxt) {
    foreach my $rr ($querytxt->answer) {
      next unless $rr->type eq "TXT";
      if(defined $debug) { print "*** Found $ip in $bl zone\n"; }
      if(defined $debug) { print "*** Record type: " . $rr->type . "\n"; }
      if ($rr->type eq "TXT") {
        $answer{$bl}->{reason} = $rr->rdatastr;
        if(defined $debug) { print "*** Reason $answer{$bl}->{reason}\n\n"; }
      }
    }
  }
}

# Decide if we're going to alert
if (%answer) {
  if(defined $debug) { print "%answer hash contents:\n" . Dumper(%answer) . "\n"; }
  if(defined $debug) { print "%answer hash scalar: " . scalar(keys %answer) . "\n"; }
  print "$ip is listed on " . scalar(keys %answer) . " blacklist(s): ";
  while(($blkey, $blvalue) = each(%answer)) {
    print $blkey . " code: " . $blvalue->{code};
    if (defined($blvalue eq "reason")) {
      print " reason: " . $blvalue->{reason} . " ";
    } else {
      print " ";
    }
    push(@exitchk, $blkey);
  } 
  EXIT: for $entry(@exitchk) {
    for $alert(@dnsblalert) {
      if ($alert eq $entry) {
        $exit = 2;
        last EXIT;
      } else {
        $exit = 1;
      }
    }
  }
  print "\n";
  if(defined $debug) { print "Exiting $exit\n"; }
  exit $exit;
} else {
  print "$ip was not found on any known blacklists\n";
  if(defined $debug) { print "Exiting $exit\n"; }
  exit $exit;
}
