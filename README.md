## Nagios plugins

####check_blacklist.pl

Generic Nagios check for blacklist monitoring

Checks an IPv4 address for the presence of an A record and TXT record on well known dnsbl zones. 
Returns a Nagios OK, alert or warning depending on the status and which array the dnsbl zone is on.

Usage: check_blacklist.pl --ip ip [--dnsbl zone[,zone,...]][--debug][--help|-?]

####check_tomcat.pl

Generic Nagios JSESSIONID check for Tomcat --rruma@fas.harvard.edu

Allows for a generic check between two requests to the given host and does
comparisons within each request to verify the JSESSIONID cookie string is
the same in the header and body content and different between each request

Usage: /usr/local/nagios2/libexec/FAS/check_tomcat.pl --hostname <fqdn> --path <path> [--port <port>][--secure][--debug][--help|-?]
