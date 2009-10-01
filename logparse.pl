#!/usr/bin/perl
# Copyright 2003, 2009 Michael Knox, mike@hfnix.net
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

=head1 NAME
logparse - syslog analysis tool
=cut

=head1 SYNOPSIS
./logparse.pl [-c <configfile> ] [-l <logfile>] [-d <debug level>]

Describe config file for log parse / summary engine
 Input fields from syslog:
  Date, time, server, application, facility, ID, message

=head3 Config line
  /server regex/, /app regex/, /facility regex/, /msg regex/, $ACTIONS
   Summaries are required at various levels, from total instances to total sizes to server summaries.

=head2 ACTIONS
 COUNT - Just list the total number of matches
 SUM[x] - Report the sum of field x of all matches
 SUM[x], /regex/ - Apply regex to msg field of matches and report the sum of field x from that regex 
 SUM[x], /regex/, {y,z} - Apply regex to msg field of matches and report the sum of field x from that regex for fields y & z
 AVG[x], /regex/, {y,z} - Apply regex to msg field of matches and report the avg of field x from that regex for fields y & z
 COUNT[x], /regex/, {y,z} - Apply regex to msg field of matches and report the count of field x from that regex for matching fields y & z

 Each entry can test or regex, if text interpret as regex /^string$/
  Sample entry...
    *, /rshd/, *, *, COUNT /connect from (.*)/, {1}

=head2 BUGS:

=head2 TODO:
=cut

# expects data on std in
use strict;
use Getopt::Std;
no strict 'refs';

my %opts;
my $CONFIGFILE="logparse.conf";
my %config;
my %results;
my $cmdcount = 0;
my $UNMATCHEDLINES = 1;
my $DEBUG = 0;
my $SYSLOGFILE = "/var/log/messages";
my %svrlastline; # hash of the last line per server, excluding 'last message repeated x times'

getopt('cdl', \%opts);
$DEBUG = $opts{d} if $opts{d};
$CONFIGFILE = $opts{c} if $opts{c};
$SYSLOGFILE = $opts{l} if $opts{l};

open (CFGFILE, "<$CONFIGFILE");
my $rule;
while (<CFGFILE>) {
	my $line = $_;
	my $cmd; my $arg;
	chomp $line;

	next if $line =~ /^#|\s+#/;
	$line = $1 if $line =~ /^\s+(.*)/;
	($cmd, $arg) = split (/\s+/, $line, 2);
	next unless $cmd;	
    logmsg (6, 0, "main(): parse cmd: $cmd arg: $arg");

 for ($cmd) {
  if (/RULE/) {
   if ($arg =~ /(.*)\s+\{/) {
    $rule = $1;
   } else {
    $rule = $cmdcount++;
   }
  } elsif (/HOST/) {
    extractregex ("svrregex", $arg);
  } elsif (/APP($|\s+)/) {
    extractregex ("appregex", $arg);
  } elsif (/FACILITY/) {
    extractregex ("facregex", $arg);
  } elsif (/MSG/) {
    extractregex ("msgregex", $arg);
  } elsif (/CMD/) {
    extractregex ("cmd", $arg)  unless $arg =~ /\{/;
  } elsif (/^REGEX/) {
    extractregexold ("cmdregex", $arg);
  } elsif (/MATCH/) {
    extractregexold ("cmdmatrix", $arg);
   $config{$rule}{cmdmatrix} =~ s/\s+//g; # strip all whitespace
  } elsif (/IGNORE/) {
   $config{$rule}{cmd} = $cmd;
  } elsif (/COUNT/) {
   $config{$rule}{cmd} = $cmd;
  } elsif (/SUM/) {
   extractregex ("targetfield", $arg);
   $config{$rule}{targetfield} =~ s/\s+//g; # strip all whitespace
   $config{$rule}{cmd} = $cmd;
  } elsif (/AVG/) {
   extractregex ("targetfield", $arg);
   $config{$rule}{targetfield} =~ s/\s+//g; # strip all whitespace
   $config{$rule}{cmd} = $cmd;
  } elsif (/TITLE/) {
   $config{$rule}{rpttitle} = $arg;
   $config{$rule}{rpttitle} = $1 if $config{$rule}{rpttitle} =~ /^\"(.*)\"$/;
  } elsif (/LINE/) {
   $config{$rule}{rptline} = $arg;
   $config{$rule}{rptline} = $1 if $config{$rule}{rptline} =~ /^\"(.*)\"$/;
  } elsif (/APPEND/) {
   $config{$rule}{appendrule} = $arg;
   logmsg (1, 0, "*** Setting append for $rule to $arg");
  } elsif (/REPORT/) {
  } elsif (/^\}$/) {
  } elsif (/^\{$/) {
  } else {
    print "Error: $cmd didn't match any known commands\n\n";
  }
 }
    logmsg (5, 1,  "main() rule: $rule");
    for my $key (keys %{ $config{$rule} } ) {
		foreach my $index (@{ $config{$rule}{$key} } ) {
         	logmsg (5, 2, "main() key=$key");
    		for my $regkey (keys %{ $index} ) {
				logmsg (5,3, "main(): $regkey=$$index{$regkey}");
			}
		}
    }
}


open (LOGFILE, "<$SYSLOGFILE") or die "Unable to open $SYSLOGFILE for reading...";
while (<LOGFILE>) {
	#my $mth; my $date; my $time; my $svr; my $app; my $msg;
	my $facility;
	my %line;
	# Placing line and line componenents into a hash to be passed to actrule, components can then be refered
	# to in action lines, ie {svr} instead of trying to create regexs to collect individual bits
	$line{line} = $_;

    logmsg (5, 1, "Processing next line");
	($line{mth}, $line{date}, $line{time}, $line{svr}, $line{app}, $line{msg}) = split (/\s+/, $line{line}, 6);
	logmsg (9, 2, "mth: $line{mth}, date: $line{date}, time: $line{time}, svr: $line{svr}, app: $line{app}, msg: $line{msg}");

	if ($line{msg} =~ /^\[/) {
		($line{facility}, $line{msg}) = split (/\]\s+/, $line{msg}, 2);
		$line{facility} =~ s/\[//;
	}

	logmsg (9, 1, "Checking line: $line{line}");
	logmsg (9, 1, "facility: $line{facility}");
	logmsg (9, 1, "msg: $line{msg}");

	my %matches;
	my %matchregex = ("svrregex", "svr", "appregex", "app", "facregex", "facility", "msgregex", "line");
	for my $param ("appregex", "facregex", "msgregex", "svrregex") {
		matchingrules($param, \%matches, $line{ $matchregex{$param} } );
	}
	$results{nomatch}[$#{$results{nomatch}}+1] = $line{line} and next unless keys %matches > 0;

    if ($line{msg} =~ /message repeated/ and exists $svrlastline{$line{svr} }{line}{msg} ) { # and keys %{$svrlastline{ $line{svr} }{rulematches}} ) {
        logmsg (9, 2, "last message repeated and matching svr line");
        my $numrepeats = 0;
        if ($line{msg} =~ /message repeated (.*) times/) {
            $numrepeats = $1;
        }
        logmsg(9, 2, "Last message repeated $numrepeats times");
        for my $i (1..$numrepeats) {
		    for my $rule (keys %{$svrlastline{ $line{svr} }{rulematches} } ) {
			    logmsg (5, 3, "Applying cmd for rule $rule: $config{$rule}{cmd} - as prelim regexs pass");
                actionrule($rule, \%{ $svrlastline{$line{svr} }{line} }); # if $actrule == 0;
            }
        }
    } else {
        logmsg (5, 2, "No recorded last line for $line{svr}") if $line{msg} =~ /message repeated/;
        logmsg (9, 2, "msg: $line{msg}");
        %{ $svrlastline{$line{svr} }{line} } = %line;
        # track line
        # track matching rule(s)

	    logmsg (3, 2, keys (%matches)." matches after checking all rules");

	    if (keys %matches > 0) {
			logmsg (5, 2, "svr & app & fac & msg matched rules: ");
			for my $key (keys %matches) {
			    logmsg (5, 3, "$key ");
			}
			logmsg (5, 2, " rules from line $line{line}");

		    # loop through matching rules and collect data as defined in the ACTIONS section of %config
		    my $actrule = 0;
            my %tmpmatches = %matches;
		    for my $rule (keys %tmpmatches) {
			    my $result = actionrule($rule, \%line);
                delete $matches{$rule} unless $result ;
                $actrule = $result unless $actrule;
			    logmsg (5, 3, "Applying cmd from rule $rule: $config{$rule}{cmd} as passed prelim regexes");
                logmsg (10, 4, "an action rule matched: $actrule");
		    }
            logmsg (10, 4, "an action rule matched: $actrule");
		    $results{nomatch}[$#{$results{nomatch}}+1] = $line{line} if $actrule == 0;
            %{$svrlastline{$line{svr} }{rulematches}} = %matches unless ($line{msg} =~ /last message repeated \d+ times/);

            logmsg (5, 2, "main(): setting lastline match for server: $line{svr} and line:\n$line{line}");
			logmsg (5, 3, "added matches for $line{svr} for rules:");
			for my $key (keys %{$svrlastline{$line{svr} }{rulematches}}) {
		        logmsg (5, 4, "$key");
            }
			logmsg (5, 3, "rules from line $line{line}");
        } else {
		    logmsg (5, 2, "No match: $line{line}") if $UNMATCHEDLINES;
            if ($svrlastline{$line{svr} }{unmatchedline}{msg} eq $line{msg} ) {
                $svrlastline{$line{svr} }{unmatchedline}{count}++;
                logmsg (9, 3, "$svrlastline{$line{svr} }{unmatchedline}{count} instances of msg: $line{msg} on $line{svr}");
            } else {
                $svrlastline{$line{svr} }{unmatchedline}{count} = 0 unless exists $svrlastline{$line{svr} }{unmatchedline}{count};
                if ($svrlastline{$line{svr} }{unmatchedline}{msg} and $svrlastline{$line{svr} }{unmatchedline}{count} >= 1) {
		            $results{nomatch}[$#{$results{nomatch}}+1] = "$line{svr}: Last unmatched message repeated $svrlastline{$line{svr} }{unmatchedline}{count} times\n";
                } else {
		            $results{nomatch}[$#{$results{nomatch}}+1] = $line{line};
                    $svrlastline{$line{svr} }{unmatchedline}{msg} = $line{msg};
                }
                $svrlastline{$line{svr} }{unmatchedline}{count} = 0;
            }
            logmsg (5, 2, "main(): set unmatched{ $line{svr} }{msg} to $svrlastline{$line{svr} }{unmatchedline}{msg} and count to: $svrlastline{$line{svr} }{unmatchedline}{count}");
        }
    }
    logmsg (5, 1, "main(): finished processing line");
}

foreach my $server (keys %svrlastline) {
    if ( $svrlastline{$server}{unmatchedline}{count} >= 1) {
        logmsg (9, 2, "main(): Added record #".( $#{$results{nomatch}} + 1 )." for unmatched results");
	    $results{nomatch}[$#{$results{nomatch}}+1] = "$server: Last unmatched message repeated $svrlastline{$server }{unmatchedline}{count} times\n";
    }
}

report();
exit 0;

sub extractregexold {
	# Keep the old behaviour

    my $param = shift;
    my $arg = shift;
	my $paramnegat = $param."negate";

    logmsg (5, 1, "extractregex(): $param $arg");
    if ($arg =~ /^\!/) {
        $arg =~ s/^\!//g;
        $config{$rule}{$paramnegat} = 1;
    } else {
        $config{$rule}{$paramnegat} = 0;
    }

# strip leading and trailing /'s
    $arg =~ s/^\///;
    $arg =~ s/\/$//;
# strip leading and trailing brace's {}
    $arg =~ s/^{//;
    $arg =~ s/}$//;
    $config{$rule}{$param} = $arg;
	logmsg (5, 2, "extractregex(): $param = $config{$rule}{$param}");

}

sub extractregex {
	# Put the matches into an array, but would need to change how we handle negates
	# Currently the negate is assigned to match group (ie facility or host) or rather than 
	# an indivudal regex, not an issue immediately because we only support 1 regex
	# Need to assign the negate to the regex
	# Make the structure ...
	#	$config{$rule}{$param}[$index] is a hash with {regex} and {negate}

    my $param = shift;
    my $arg = shift;
	my $index = @{$config{$rule}{$param}};
	$index = 0 if $index == "";

	my $regex = \%{$config{$rule}{$param}[$index]};

	$$regex{negate} = 0;

    logmsg (5, 1, "extractregex(): $param $arg");
    if ($arg =~ /^\!/) {
        $arg =~ s/^\!//g;
		$$regex{negate} = 1;
    }

# strip leading and trailing /'s
    $arg =~ s/^\///;
    $arg =~ s/\/$//;
# strip leading and trailing brace's {}
    $arg =~ s/^{//;
    $arg =~ s/}$//;
	$$regex{regex} = $arg;
	logmsg (9, 3, "extractregex(): \$regex\{regex\} = $$regex{regex} & \$regex\{negate\} = $$regex{negate}");

	logmsg (5,2, "extractregex(): \$index = $index");
    logmsg (5, 2, "extractregex(): $param \[$index\]\{regex\} = $config{$rule}{$param}[$index]{regex}");
    logmsg (5, 2, "extractregex(): $param \[$index\]\{negate\} = $config{$rule}{$param}[$index]{negate}");

	for (my $i=0; $i<=$index; $i++) 
	{ 
		logmsg (5,1, "extractregex(): index: $i");
		foreach my $key (keys %{$config{$rule}{$param}[$i]}) {
    		logmsg (5, 2, "extractregex(): $param \[$i\]\{$key\} = $config{$rule}{$param}[$i]{$key}");
		}
	}
}

sub report {
	print "\n\nNo match for lines:\n";
	foreach my $line (@{$results{nomatch}}) {
		print "\t$line";
	}
	print "\n\nSummaries:\n";
	for my $rule (sort keys %results)  {
		next if $rule =~ /nomatch/;
		if (exists ($config{$rule}{rpttitle})) {
			print "$config{$rule}{rpttitle}:\n";
		} else {
			logmsg (4, 2, "Rule: $rule:");
		}

		for my $key (keys %{$results{$rule}} )  {
			if (exists ($config{$rule}{rptline})) {
				print "\t".rptline($rule, $key)."\n";
			} else {
				print "\t$results{$rule}{$key}: $key\n";
			}
		}
		print "\n";
	}
}

sub rptline {
	my $rule = shift;
	my $key = shift;
	my $line = $config{$rule}{rptline};
	# generate rpt line based on config spec for line and results.
	# Sample entry: {x}: logouts from {2} by {1}

    logmsg (9, 2, "rptline():");
    logmsg (9, 3, "key: $key");
	my @fields = split /:/, $key;

    logmsg (9, 3, "line: $line");
	$line =~ s/\{x\}/$results{$rule}{$key}{count}/;
    
    if ($config{$rule}{cmd} eq "SUM") {
	    $line =~ s/\{s\}/$results{$rule}{$key}{sum}/;
    }
    if ($config{$rule}{cmd} eq "AVG") {
        my $avg = $results{$rule}{$key}{sum} / $results{$rule}{$key}{count};
        $avg = sprintf ("%.3f", $avg);
	    $line =~ s/\{a\}/$avg/;
    }

    logmsg (9, 3, "rptline(): #fields ".($#fields+1)." in \@fields");
	for my $i (0..$#fields) {
		my $field = $i+1;
    #my $field = $#fields;
	#for ($field; $field >= 0; $field--) {
	#for my $i ($#fields..0) {
	#	my $field = $i+1;
        logmsg (9, 4, "rptline(): \$fields[$field] = $fields[$i]");
		if ($line =~ /\{$field\}/) {
			$line =~ s/\{$field\}/$fields[$i]/;
		}
	}
	return $line;
}

sub actionrule {
	# Collect data for rule $rule as defined in the ACTIONS section of %config
	my $rule = shift;
	my $line = shift; # hash passed by ref, DO NOT mod
	my $value;
	my $retval = 0; my $resultsrule;

    logmsg (9, 2, "actionrule()");
	if (exists ($config{$rule}{appendrule})) {
	 $resultsrule = $config{$rule}{appendrule};
	} else {
	 $resultsrule = $rule;
	}
	logmsg (5, 3, "actionrule(): rule: $rule");
    logmsg (5, 4, "results goto: $resultsrule");
    logmsg (5, 4, "cmdregex: $config{$rule}{cmdregex}");
    logmsg (5, 4, "CMD negative regex: $config{$rule}{cmdregexnegat}");
    logmsg (5, 4, "line: $$line{line}");
	if ($config{$rule}{cmd} and $config{$rule}{cmd} =~ /IGNORE/) {
        if (exists ($config{$rule}{cmdregex}) ) {
		    if ($config{$rule}{cmdregex} and $$line{line} =~  /$config{$rule}{cmdregex}/ ) {
			    logmsg (5, 4, "actionrule(): rule $rule does matches and is a positive IGNORE rule");
            }
		} else {
			logmsg (5, 4, "actionrule(): rule $rule matches and is an IGNORE rule");
		    $retval = 1;
		}

		#} elsif ($config{$rule}{cmdregexnegat} and $config{$rule}{cmdregex} and $$line{line} !~  /$config{$rule}{cmdregex}/ ) {
		#	$retval = 0;
		#	print "\tactionrule(): rule $rule doesn't match and is a negative IGNORE rule\n" if $DEBUG >= 5;

	#} elsif ($$line{line}  =~  /$config{$rule}{cmdregex}/ ) {
    } elsif (exists ($config{$rule}{cmdregex}) ) {
	    if ( not $config{$rule}{cmdregexnegat} ) {
            if ( $$line{line}  =~  /$config{$rule}{cmdregex}/ )  {
                logmsg (5, 4, "actionrule(): Positive match, calling actionrulecmd");
                actionrulecmd($line, $rule, $resultsrule);
    		    $retval = 1;
            }
        } elsif ($config{$rule}{cmdregexnegat}) {
            if ( $$line{line}  !~  /$config{$rule}{cmdregex}/ ) {
                logmsg (5, 4, "actionrule(): Negative match, calling actionrulecmd");
                actionrulecmd($line, $rule, $resultsrule);
    		    $retval = 1;
            }
        }
    } else {
        logmsg (5, 4, "actionrule(): No cmd regex, implicit match, calling actionrulecmd");
        actionrulecmd($line, $rule, $resultsrule);
    	$retval = 1;
    }
    if ($retval == 0) {
		logmsg (5, 4, "actionrule(): line does not match cmdregex for rule: $rule");
		#logmsg (5, 4, "actionrule(): cmdregex: $config{$rule}{cmdregex} line: $$line{line}");
	} 
	return $retval;
}
sub actionrulecmd
{
	my $line = shift; # hash passed by ref, DO NOT mod
    my $rule = shift;
    my $resultsrule = shift;
    logmsg (2, 2, "actionrulecmd(): actioning rule $rule for line: $$line{line}");
    if (not $config{$rule}{cmdregex}) {
        $config{$rule}{cmdregex} = "(.*)";
	    logmsg (5, 3, "actionrulecmd(): rule did not define cmdregex, replacing with global match");
    }
    if ( exists $config{$rule}{cmd}) {
        logmsg (5, 3, "actionrulecmd(): Collecting data from cmd $config{$rule}{cmd}");
	    logmsg (5, 3, "actionrulecmd(): rule $rule matches cmd") if $$line{msg}  =~ /$config{$rule}{cmdregex}/;
    }

   if (not exists ($config{$rule}{cmdregex}) ) {
        logmsg (5, 3, "actionrulecmd(): No cmd regex, calling actioncmdmatrix");
        actioncmdmatrix($line, $rule, $resultsrule);
    } elsif ($config{$rule}{cmdregexnegat} ) {
        if ($config{$rule}{cmdregex} and $$line{msg} and $$line{msg}  !~ /$config{$rule}{cmdregex}/ ) {
            logmsg (5, 3, "\tactionrulecmd(): Negative match, calling actioncmdmatrix");
            actioncmdmatrix($line, $rule, $resultsrule);
        }
    } else {
        if ($config{$rule}{cmdregex} and $$line{msg} and $$line{msg}  =~ /$config{$rule}{cmdregex}/ ) {
            logmsg (5, 3, "actionrulecmd(): Positive match, calling actioncmdmatrix");
            printhash ($line);
            actioncmdmatrix($line, $rule, $resultsrule);
		} 
    } 
}

sub printhash
{
	my $line = shift; # hash passed by ref, DO NOT mod
    foreach my $key (keys %{ $line} )
    {
        logmsg (9, 5, "$key: $$line{$key}");

    }
}

sub actioncmdmatrix
{
	my $line = shift; # hash passed by ref, DO NOT mod
    my $rule = shift; # Name or ID of rule thats been matched
    my $resultsrule = shift; # Name or ID of rule which contains the result set to be updated
	my $cmdmatrix = $config{$rule}{cmdmatrix};
	my $fieldhash;
	my $cmdfield;
	my @matrix = split (/,/, $cmdmatrix);
	# @matrix - array of parameters that are used in results
	if ( exists ($config{$rule}{cmdfield}) ) {
		$cmdfield = ${$config{$rule}{cmdfield}};
	}

    logmsg(5, 2, "Entering actioncmdmatrix():");
    logmsg(6, 3, "resultsrule = $rule");
    
	if ( exists $config{$rule}{cmdmatrix}) {
	    logmsg (5, 3, "actioncmdmatrix(): Collecting data for matrix $config{$rule}{cmdmatrix}");

		foreach my $field (@matrix) {
            # This is were the black magic occurs, ${$field} causes becomes $1 or $2 etc
            # and hence contains the various matches from the previous regex match
            # which occured just before this function was called
		    logmsg (9, 4, "actioncmdmatrix(): matrix field $field has value ${$field}");
			if (exists $$line{$field}) {
				if ($fieldhash) {
					$fieldhash = "$fieldhash:$$line{$field}";
				} else {
					$fieldhash = "$$line{$field}";
				}
			} else {
				if ($fieldhash) {
				    $fieldhash = "$fieldhash:${$field}";
				} else {
				    if ( ${$field} ) {
						$fieldhash = "${$field}";
					} else {
						logmsg (1, 4, "actioncmdmatrix(): $field not found in \"$$line{line}\" with regex $config{$rule}{cmdregex}");
                        printhash($line);
					}
				}
			}
		}

        if ($config{$rule}{targetfield}) {
			logmsg (1, 4, "actioncmdmatrix(): Setting cmdfield (field $config{$rule}{targetfield}) to ${$config{$rule}{targetfield}}");
            $cmdfield = ${$config{$rule}{targetfield}};
        }
		#if ($config{$rule}{cmd} and $config{$rule}{cmd} =~ /^COUNT$/) { 
	    $results{$resultsrule}{$fieldhash}{count}++;
		logmsg (5, 4, "actioncmdmatrix(): $results{$resultsrule}{$fieldhash}{count} matches for rule $rule so far from $fieldhash");
		#} els
        if ($config{$rule}{cmd} eq "SUM" or $config{$rule}{cmd} eq "AVG") { 
			$results{$resultsrule}{$fieldhash}{sum} = $results{$resultsrule}{$fieldhash}{sum} + $cmdfield;
			logmsg (5, 4, "actioncmdmatrix(): Adding $cmdfield to total (now $results{$resultsrule}{$fieldhash}{sum}) for rule $rule so far from $fieldhash");
            if ($config{$rule}{cmd} eq "AVG") {
			    logmsg (5, 4, "actioncmdmatrix(): Average is ".$results{$resultsrule}{$fieldhash}{sum} / $results{$resultsrule}{$fieldhash}{count}." for rule $rule so far from $fieldhash");
            }
		}	
		for my $key (keys %{$results{$resultsrule}})  {
			logmsg (5, 3, "actioncmdmatrix(): key $key for rule:$rule with $results{$resultsrule}{$key}{count} matches");
		}
		logmsg (5, 2, "actioncmdmatrix(): $fieldhash matches for rule $rule so far from matrix: $config{$rule}{cmdmatrix}");
	} else {
		logmsg (5, 2, "actioncmdmatrix(): cmdmatrix is not set for $rule");
	    #if ($config{$rule}{cmd} and $config{$rule}{cmd} =~ /^COUNT$/) { 
			$results{$resultsrule}{count}++;
			logmsg (5, 3, "actioncmdmatrix(): $results{$resultsrule}{count} lines match rule $rule so far");
	#	} els
        if ($config{$rule}{cmd} eq "SUM" or $config{$rule}{cmd} eq "AVG") { 
			$results{$resultsrule}{sum} = $results{$resultsrule}{sum} + $cmdfield;
			logmsg (5, 3, "actioncmdmatrix(): $results{$resultsrule}{sum} lines match rule $rule so far");
		}
    }
}

sub defaultregex {
	# expects a reference to the rule and param
	my $paramref = shift;

	if (defined $$paramref[0]{regex} ) {
		logmsg(9, 4, "defaultregex(): Skipping, there are already regex hashes in this rule/param match");
		logmsg(9, 5, "defaultregex(): regex[0]regex = $$paramref[0]{regex}");
		logmsg(9, 5, "defaultregex(): regex[0]negate = $$paramref[0]{negate}");
	} else {
		logmsg(9, 1, "defaultregex(): There's no regex hash for this rule/param so setting defaults");
		$$paramref[0]{regex} = "(.*)";
		$$paramref[0]{negate} = 0 ;
	}
}

sub matchregex {
	# expects a reference to a regex for a given rule & param 
	# For a given rules regex hash, return true/false for a match
	my $regex = shift;
	my $value = shift;
	my $match = 0;

	if ($value =~ /$$regex{regex}/ or  $$regex{regex} =~ /^\*$/ ) { 
		#logmsg (5, 4, "Matches rule: $rule");
		$match = 1;
	} 
}

sub matchingrules {
	my $param = shift;
	my $matches = shift;
	my $value = shift;

    logmsg (3, 2, "\nmatchingrules(): param: $param, match count: ".keys(%{$matches})." value: $value");

	if (keys %{$matches} == 0) {
		# Check all rules as we haevn't had a match yet
		foreach my $rule (keys %config) {
			checkrule($param, $matches, $rule, $value);
		}
	} else {
		# As we've allready had a match on the rules, only check those that matched in earlier rounds
		# key in %matches is the rule that matches
		foreach my $rule (keys %{$matches}) {
			checkrule($param, $matches, $rule, $value);
		}
	}
}

sub checkrule {
	my $param = shift;
	my $matches = shift;
	my $rule = shift; # key to %matches
	my $value = shift;

	logmsg(2, 1, "checkrule(): Checking rule ($rule) & param ($param) for matches against: $value");

	my $paramref = \@{ $config{$rule}{$param} };
	defaultregex($paramref); # This should be done when reading the config

	foreach my $index (@{ $paramref } ) {
		my $match  = matchregex($index, $value);

		if ($$index{negate} ) {
			if ( $match) {
				delete $$matches{$rule};
				logmsg (5, 5, "checkrules(): matches $index->{regex} for param \'$param\', but negative rule is set, so removing rule $match from list.");
             } else {
				$$matches{$rule} = "match" if $match;
				logmsg (5, 5, "checkrules(): Doesn't match for $index->{regex} for param \'$param\', but negative rule is set, so leaving rule $match on list.");
             }
		} elsif ($match) {
			$$matches{$rule} = "match" if $match;
			logmsg (5, 4, "checkrules(): matches $index->{regex} for param \'$param\', leaving rule $match on list.");
		} else {
			delete $$matches{$rule};
			logmsg (5, 4, "checkrules(): doesn't match $index->{regex} for param \'$param\', removing rule $match from list.");
        }
	} # for each regex hash in the array
	logmsg (3, 2, "checkrules(): matches ".keys (%{$matches})." matches after checking rules for $param");
}

=oldcode
sub matchingrules {
	my $param = shift;
	my $matches = shift;
	my $value = shift;

    logmsg (3, 2, "matchingrules(): param: $param, matches: $matches, value: $value");
	if (keys %{$matches} == 0) {
		# Check all rules as we haevn't had a match yet
		foreach my $rule (keys %config) {
			$config{$rule}{$param} = "(.*)" unless exists ($config{$rule}{$param});
			logmsg (5, 3, "Does $value match /$config{$rule}{$param}/ ??");
			if ($value =~ /$config{$rule}{$param}/ or  $config{$rule}{$param} =~ /^\*$/ ) { 
				logmsg (5, 4, "Matches rule: $rule");
				$$matches{$rule} = "match";
			}
		}
	} else {
		# As we've allready had a match on the rules, only check those that matched in earlier rounds
		foreach my $match (keys %{$matches}) {
			if (exists ($config{$match}{$param}) ) {
				logmsg (5, 4, "Does value: \"$value\" match \'$config{$match}{$param}\' for param $param ??");
                if ($config{$match}{"${param}negat"}) {
                    logmsg (5, 5, "Doing a negative match");
                }
			} else {
				logmsg (5, 3, "No rule for value: \"$value\" in rule $match, leaving on match list.");
				$config{$match}{$param} = "(.*)";
			}
            if ($config{$match}{"${param}negat"}) {
                if ($value =~ /$config{$match}{$param}/ or  $config{$match}{$param} =~ /^\*$/ ) { 
				    delete $$matches{$match};
				    logmsg (5, 5, "matches $config{$match}{$param} for param \'$param\', but negative rule is set, so removing rule $match from list.");
                } else {
				    logmsg (5, 5, "Doesn't match for $config{$match}{$param} for param \'$param\', but negative rule is set, so leaving rule $match on list.");
                }
            } elsif ($value =~ /$config{$match}{$param}/ or  $config{$match}{$param} =~ /^\*$/ ) { 
				logmsg (5, 4, "matches $config{$match}{$param} for param \'$param\', leaving rule $match on list.");
			} else {
				delete $$matches{$match};
				logmsg (5, 4, "doesn't match $config{$match}{$param} for param \'$param\', removing rule $match from list.");
            }
		}
	}
	logmsg (3, 2, keys (%{$matches})." matches after checking rules for $param");
}
=cut

sub logmsg {
    my $level = shift;
    my $indent = shift;
    my $msg = shift;

    if ($DEBUG >= $level) {
        for my $i (0..$indent) {
            print STDERR "  ";
        }
        print STDERR "$msg\n";
    }
}

