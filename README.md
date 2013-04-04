Random scripts I've written that someone may find useful.
==================

check_blacklist.pl

Generic Nagios check for blacklist monitoring

Checks an IPv4 address for the presence of an A record and TXT record on well known dnsbl zones. 
Returns a Nagios OK, alert or warning depending on the status and which array the dnsbl zone is on.

Usage: check_blacklist.pl --ip ip [--dnsbl zone[,zone,...]][--debug][--help|-?]
