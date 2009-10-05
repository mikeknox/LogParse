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
	See http://github.com/mikeknox/LogParse/issues

=head2 FORMAT stanza
FORMAT <name> {
   DELIMITER <xyz>
   FIELDS <x>
   FIELD<x> <name>
}

=head2 TODO:

=head3 Config hash design
	The config hash needs to be redesigned, particuarly to support other input log formats.
	current layout:
	all parameters are members of $$cfghashref{rules}{$rule}

	Planned:
	$$cfghashref{rules}{$rule}{fields} - Hash of fields
	$$cfghashref{rules}{$rule}{fields}{$field} - Array of regex hashes
	$$cfghashref{rules}{$rule}{cmd} - Command hash
	$$cfghashref{rules}{$rule}{report} -  Report hash
=head3 Command hash
	Config for commands such as COUNT, SUM, AVG etc for a rule
	$cmd

=head3 Report hash
	Config for the entry in the report / summary report for a rule

=head3 regex hash
	$regex{regex} = regex string
	$regex{negate} = 1|0 - 1 regex is to be negated

=cut

# expects data on std in
use strict;
use Getopt::Std;
#no strict 'refs';
#use Data::Dump qw(pp);
use Data::Dumper qw(Dumper);

#use utils;
#use logparse;

# Globals
my %profile;
my $DEBUG = 0;
my %DEFAULTS = ("CONFIGFILE", "logparse.conf", "SYSLOGFILE", "/var/log/messages" );
my %opts;
my $CONFIGFILE="logparse.conf";
my %cfghash;
my %reshash;
my $cmdcount = 0;
my $UNMATCHEDLINES = 1;
my $SYSLOGFILE = "/var/log/messages";
my %svrlastline; # hash of the last line per server, excluding 'last message repeated x times'

getopt('cdl', \%opts);
$DEBUG = $opts{d} if $opts{d};
$CONFIGFILE = $opts{c} if $opts{c};
$SYSLOGFILE = $opts{l} if $opts{l};

loadcfg (\%cfghash, $CONFIGFILE, $cmdcount);

processlogfile(\%cfghash, \%reshash, $SYSLOGFILE);

report(\%cfghash, \%reshash);

profilereport();
exit 0;

sub processlogfile {
	my $cfghashref = shift;
	my $reshashref = shift;
	my $logfile = shift;

	logmsg (1, 0, "processing $logfile ...");
	logmsg(5, 1, " and I was called by ... ".&whowasi);
	open (LOGFILE, "<$logfile") or die "Unable to open $SYSLOGFILE for reading...";
	while (<LOGFILE>) {
		my $facility;
		my %line;
		# Placing line and line componenents into a hash to be passed to actrule, components can then be refered
		# to in action lines, ie {svr} instead of trying to create regexs to collect individual bits
		$line{line} = $_;

    	logmsg (5, 1, "Processing next line");
		($line{mth}, $line{date}, $line{time}, $line{svr}, $line{app}, $line{msg}) = split (/\s+/, $line{line}, 6);
		logmsg (9, 2, "mth: $line{mth}, date: $line{date}, time: $line{time}, svr: $line{svr}, app: $line{app}, msg: $line{msg}");

		if ($line{msg} =~ /^\[/) {
			($line{facility}, $line{msg}) = split (/]\s+/, $line{msg}, 2);
			$line{facility} =~ s/\[//;
		}
	
		logmsg (9, 1, "Checking line: $line{line}");
		logmsg (9, 1, "facility: $line{facility}");
		logmsg (9, 1, "msg: $line{msg}");

		my %matches;
		my %matchregex = ("svrregex", "svr", "appregex", "app", "facregex", "facility", "msgregex", "line");
		for my $param ("appregex", "facregex", "msgregex", "svrregex") {
			matchingrules($cfghashref, $param, \%matches, $line{ $matchregex{$param} } );
		}
		logmsg(9, 2, keys(%matches)." matches so far");
		$$reshashref{nomatch}[$#{$$reshashref{nomatch}}+1] = $line{line} and next unless keys %matches > 0;
		logmsg(9,1,"Results hash ...");
		Dumper(%$reshashref);
	
    	if ($line{msg} =~ /message repeated/ and exists $svrlastline{$line{svr} }{line}{msg} ) { # and keys %{$svrlastline{ $line{svr} }{rulematches}} ) {
        	logmsg (9, 2, "last message repeated and matching svr line");
        	my $numrepeats = 0;
        	if ($line{msg} =~ /message repeated (.*) times/) {
            	$numrepeats = $1;
        	}
        	logmsg(9, 2, "Last message repeated $numrepeats times");
        	for my $i (1..$numrepeats) {
		    	for my $rule (keys %{$svrlastline{ $line{svr} }{rulematches} } ) {
			    	logmsg (5, 3, "Applying cmd for rule $rule: $$cfghashref{rules}{$rule}{cmd} - as prelim regexs pass");
                	actionrule($cfghashref, $reshashref, $rule, \%{ $svrlastline{$line{svr} }{line} }); # if $actrule == 0;
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
				logmsg (5, 2, "matched rules ".keys(%matches)." from line $line{line}");

		    	# loop through matching rules and collect data as defined in the ACTIONS section of %config
		    	my $actrule = 0;
            	my %tmpmatches = %matches;
		    	for my $rule (keys %tmpmatches) {
			    	my $result = actionrule($cfghashref, $reshashref, $rule, \%line);
                	delete $matches{$rule} unless $result ;
                	$actrule = $result unless $actrule;
			    	logmsg (5, 3, "Applying cmd from rule $rule: $$cfghashref{rules}{$rule}{cmd} as passed prelim regexes");
                	logmsg (10, 4, "an action rule matched: $actrule");
		    	}
            	logmsg (10, 4, "an action rule matched: $actrule");
		    	$$reshashref{nomatch}[$#{$$reshashref{nomatch}}+1] = $line{line} if $actrule == 0;
            	%{$svrlastline{$line{svr} }{rulematches}} = %matches unless ($line{msg} =~ /last message repeated d+ times/);

            	logmsg (5, 2, "setting lastline match for server: $line{svr} and line:\n$line{line}");
				logmsg (5, 3, "added matches for $line{svr} for rules:");
				for my $key (keys %{$svrlastline{$line{svr} }{rulematches}}) {
		        	logmsg (5, 4, "$key");
            	}
				logmsg (5, 3, "rules from line $line{line}");
        	} else {
		    	logmsg (5, 2, "No match: $line{line}");
            	if ($svrlastline{$line{svr} }{unmatchedline}{msg} eq $line{msg} ) {
                	$svrlastline{$line{svr} }{unmatchedline}{count}++;
                	logmsg (9, 3, "$svrlastline{$line{svr} }{unmatchedline}{count} instances of msg: $line{msg} on $line{svr}");
            	} else {
                	$svrlastline{$line{svr} }{unmatchedline}{count} = 0 unless exists $svrlastline{$line{svr} }{unmatchedline}{count};
                	if ($svrlastline{$line{svr} }{unmatchedline}{msg} and $svrlastline{$line{svr} }{unmatchedline}{count} >= 1) {
		            	$$reshashref{nomatch}[$#{$$reshashref{nomatch}}+1] = "$line{svr}: Last unmatched message repeated $svrlastline{$line{svr} }{unmatchedline}{count} timesn";
                	} else {
		            	$$reshashref{nomatch}[$#{$$reshashref{nomatch}}+1] = $line{line};
                    	$svrlastline{$line{svr} }{unmatchedline}{msg} = $line{msg};
                	}
                	$svrlastline{$line{svr} }{unmatchedline}{count} = 0;
            	}
            	logmsg (5, 2, "set unmatched{ $line{svr} }{msg} to $svrlastline{$line{svr} }{unmatchedline}{msg} and count to: $svrlastline{$line{svr} }{unmatchedline}{count}");
        	}
    	}
    	logmsg (5, 1, "finished processing line");
	}

	foreach my $server (keys %svrlastline) {
   		if ( $svrlastline{$server}{unmatchedline}{count} >= 1) {
       		logmsg (9, 2, "Added record #".( $#{$$reshashref{nomatch}} + 1 )." for unmatched results");
    		$$reshashref{nomatch}[$#{$$reshashref{nomatch}}+1] = "$server: Last unmatched message repeated $svrlastline{$server }{unmatchedline}{count} timesn";
		}
	}
	logmsg (1, 0, "Finished processing $logfile.");
}

sub parsecfgline {
	my $line = shift;

	#profile( whoami(), whowasi() );
	logmsg (5, 3, " and I was called by ... ".&whowasi);
	my $cmd = "";
	my $arg = "";
	chomp $line;

	logmsg(5, 3, " and I was called by ... ".&whowasi);
	logmsg (6, 4, "line: ${line}");

	if ($line =~ /^#|\s+#/ ) {
		logmsg(9, 4, "comment line, skipping, therefore returns are empty strings");
	} elsif ($line =~ /^\s+$/ or $line =~ /^$/ ){
		logmsg(9, 4, "empty line, skipping, therefore returns are empty strings");
	} else {
		$line = $1 if $line =~ /^\s+(.*)/;
		($cmd, $arg) = split (/\s+/, $line, 2);
		$arg = "" unless $arg;
		$cmd = "" unless $cmd;	
	}
	
	logmsg (6, 3, "returning cmd: $cmd arg: $arg");
	return ($cmd, $arg);
}

sub loadcfg {
	my $cfghashref = shift;
	my $cfgfile = shift;
	my $cmdcount = shift;

	open (CFGFILE, "<$cfgfile");

	logmsg(1, 0, "Loading cfg from $cfgfile");
	logmsg(5, 3, " and I was called by ... ".&whowasi);
	
	my $rule = -1;
	my $bracecount = 0;
	my $stanzatype = "";

	while (<CFGFILE>) {
		my $line = $_;

		logmsg(5, 1, "line: $line");
		logmsg(6, 2, "bracecount:$bracecount");
		logmsg(6, 2, "stanzatype:$stanzatype");

		my $cmd; my $arg;
		($cmd, $arg) = parsecfgline($line);
		next unless $cmd;
		logmsg(6, 2, "rule:$rule");
		logmsg(6, 2, "cmdcount:$cmdcount");
		logmsg (6, 2, "cmd:$cmd arg:$arg rule:$rule cmdcount:$cmdcount");

		if ($bracecount == 0 ) {
 			for ($cmd) {
  				if (/RULE/) {
   					if ($arg =~ /(.*)\s+\{/) {
    					$rule = $1;
						logmsg (9, 3, "rule (if) is now: $rule");
   					} else {
    					$rule = $cmdcount++;
						logmsg (9, 3, "rule (else) is now: $rule");
   					} # if arg
					$stanzatype = "rule";
					logmsg(6, 2, "stanzatype updated to: $stanzatype");
					logmsg(6, 2, "rule updated to:$rule");
				} elsif (/FORMAT/) {
   					if ($arg =~ /(.*)\s+\{/) {
    					$rule = $1;
   					} # if arg
					$stanzatype = "format";
					logmsg(6, 2, "stanzatype updated to: $stanzatype");
				} elsif (/\}/) {
					# if bracecount = 0, cmd may == "}", so ignore
				} else {
    				print STDERR "Error: $cmd didn't match any stanzasn\n";
				} # if cmd
			} # for cmd
		} # bracecount == 0
		if  ($cmd =~ /\{/ or $arg =~ /\{/) {
				$bracecount++;
		} elsif  ($cmd =~ /\}/ or $arg =~ /\}/) {
				$bracecount--;
		} # if cmd or arg

		if ($bracecount > 0) { # else bracecount
			for ($stanzatype) {
				if (/rule/) {
					logmsg (6, 2, "About to call processrule ... cmd:$cmd arg:$arg rule:$rule cmdcount:$cmdcount");
					processrule( \%{ $$cfghashref{rules}{$rule} }, $rule, $cmd, $arg);
				} elsif (/format/) {
					logmsg (6, 2, "About to call processformat ... cmd:$cmd arg:$arg rule:$rule cmdcount:$cmdcount");
					processformat( \%{$$cfghashref{formats}{$rule}} , $rule, $cmd, $arg);
				} # if stanzatype
			} #if stanzatype
		} else {# else bracecount
			logmsg (1, 2, "ERROR: bracecount: $bracecount. How did it go negative??");
		} # bracecount
	} # while
	close CFGFILE;
	logmsg (5, 1, "Config Hash contents:");
	&Dumper( %$cfghashref );
	logmsg (1, 0, "finished processing cfg: $cfgfile");
} # sub loadcfg

sub processformat {
	my $cfghashref = shift;
	my $rule = shift;	# name of the rule to be processed
	my $cmd = shift;
	my $arg = shift;

	#profile( whoami(), whowasi() );
	logmsg (5, 4, " and I was called by ... ".&whowasi);
	logmsg (5, 4, "Processing rule: $rule");
	logmsg(9, 5, "passed cmd: $cmd");
	logmsg(9, 5, "passed arg: $arg");
	next unless $cmd;

		for ($cmd) {
			if (/DELIMITER/) {
				$$cfghashref{delimiter} = $arg;
				logmsg (5, 1, "Config Hash contents:");
				&Dumper( %$cfghashref );
			} elsif (/FIELDS/) {
				$$cfghashref{fields} = $arg;
			} elsif (/FIELD(\d+)/) {
				logmsg(6, 6, "FIELD#: $1 arg:$arg");
  			} elsif (/^\}$/) {
  			} elsif (/^\{$/) {
  			} else {
    			print "Error: $cmd didn't match any known fields\n\n";
			} # if cmd
		} # for cmd
	logmsg (5, 4, "Finished processing rule: $rule");
} # sub processformat

sub processrule {
	my $cfghashref = shift;
	my $rule = shift;	# name of the rule to be processed
	my $cmd = shift;
	my $arg = shift;

	#profile( whoami(), whowasi() );
	logmsg (5, 4, " and I was called by ... ".&whowasi);
	logmsg (5, 4, "Processing $rule with cmd: $cmd and arg: $arg");

	next unless $cmd;
	for ($cmd) {
		if (/HOST/) {
			# fields
    		extractregex ($cfghashref, "svrregex", $arg, $rule);
  		} elsif (/APP($|\s+)/) {
    		extractregex ($cfghashref, "appregex", $arg, $rule);
  		} elsif (/FACILITY/) {
    		extractregex ($cfghashref, "facregex", $arg, $rule);
  		} elsif (/MSG/) {
    		extractregex ($cfghashref, "msgregex", $arg, $rule);
  		} elsif (/CMD/) {
    		extractregex ($cfghashref, "cmd", $arg, $rule)  unless $arg =~ /\{/;
  		} elsif (/^REGEX/) {
    		extractregexold ($cfghashref, "cmdregex", $arg, $rule);
		} elsif (/MATCH/) {
			extractregexold ($cfghashref, "cmdmatrix", $arg, $rule);
   			$$cfghashref{cmdmatrix} =~ s/\s+//g; # strip all whitespace
  		} elsif (/IGNORE/) {
   			$$cfghashref{cmd} = $cmd;
  		} elsif (/COUNT/) {
   			$$cfghashref{cmd} = $cmd;
  		} elsif (/SUM/) {
   			extractregex ($cfghashref, "targetfield", $arg, $rule);
   			$$cfghashref{targetfield} =~ s/\s+//g; # strip all whitespace
   			$$cfghashref{cmd} = $cmd;
  		} elsif (/AVG/) {
   			extractregex ($cfghashref, "targetfield", $arg, $rule);
   			$$cfghashref{targetfield} =~ s/\s+//g; # strip all whitespace
   			$$cfghashref{cmd} = $cmd;
  		} elsif (/TITLE/) {
   			$$cfghashref{rpttitle} = $arg;
   			$$cfghashref{rpttitle} = $1 if $$cfghashref{rpttitle} =~ /^\"(.*)\"$/;
  		} elsif (/LINE/) {
   			$$cfghashref{rptline} = $arg;
   			$$cfghashref{rptline} = $1 if $$cfghashref{rptline} =~ /\^"(.*)\"$/;
  		} elsif (/APPEND/) {
   			$$cfghashref{appendrule} = $arg;
   			logmsg (1, 0, "*** Setting append for $rule to $arg");
  		} elsif (/REPORT/) {
  		} elsif (/^\}$/) {
		#	$bracecount{closed}++;
  		} elsif (/^\{$/) {
		#	$bracecount{open}++;
  		} else {
    		print "Error: $cmd didn't match any known fields\n\n";
  		}
	} # for
    logmsg (5, 1,  "Finished processing rule: $rule");
	logmsg (9, 1, "Config hash after running processrule");
	Dumper(%$cfghashref);
} # sub processrule

sub extractregexold {
	# Keep the old behaviour
	my $cfghashref = shift;
    my $param = shift;
    my $arg = shift;
	my $rule = shift;

#	profile( whoami(), whowasi() );
	logmsg (5, 3, " and I was called by ... ".&whowasi);
	my $paramnegat = $param."negate";

    logmsg (5, 1, "rule: $rule param: $param arg: $arg");
    if ($arg =~ /^!/) {
        $arg =~ s/^!//g;
        $$cfghashref{$paramnegat} = 1;
    } else {
        $$cfghashref{$paramnegat} = 0;
    }

# strip leading and trailing /'s
    $arg =~ s/^\///;
    $arg =~ s/\/$//;
# strip leading and trailing brace's {}
    $arg =~ s/^\{//;
    $arg =~ s/\}$//;
    $$cfghashref{$param} = $arg;
	logmsg (5, 2, "$param = $$cfghashref{$param}");
}

sub extractregex {
	# Put the matches into an array, but would need to change how we handle negates
	# Currently the negate is assigned to match group (ie facility or host) or rather than 
	# an indivudal regex, not an issue immediately because we only support 1 regex
	# Need to assign the negate to the regex
	# Make the structure ...
	#	$$cfghashref{rules}{$rule}{$param}[$index] is a hash with {regex} and {negate}

	my $cfghashref = shift;
    my $param = shift;
    my $arg = shift;
	my $rule = shift;

	my $index = 0;

#	profile( whoami(), whowasi() );
	logmsg (5, 3, " and I was called by ... ".&whowasi);
	logmsg (1, 3, " rule: $rule for param $param with arg $arg ");
	if (exists $$cfghashref{$param}[0] ) {
		$index = @{$$cfghashref{$param}};
	} else {
		$$cfghashref{$param} = ();
	}

	my $regex = \%{$$cfghashref{$param}[$index]};

	$$regex{negate} = 0;

    logmsg (5, 1, "$param $arg");
    if ($arg =~ /^!/) {
        $arg =~ s/^!//g;
		$$regex{negate} = 1;
    }

# strip leading and trailing /'s
    $arg =~ s/^\///;
    $arg =~ s/\/$//;
# strip leading and trailing brace's {}
    $arg =~ s/^{//;
    $arg =~ s/}$//;
	$$regex{regex} = $arg;
	logmsg (9, 3, "$regex\{regex\} = $$regex{regex} & \$regex\{negate\} = $$regex{negate}");

	logmsg (5,2, "$index = $index");
    logmsg (5, 2, "$param \[$index\]\{regex\} = $$cfghashref{$param}[$index]{regex}");
    logmsg (5, 2, "$param \[$index\]\{negate\} = $$cfghashref{$param}[$index]{negate}");

	for (my $i=0; $i<=$index; $i++) 
	{ 
		logmsg (5,1, "index: $i");
		foreach my $key (keys %{$$cfghashref{$param}[$i]}) {
    		logmsg (5, 2, "$param \[$i\]\{$key\} = $$cfghashref{$param}[$i]{$key}");
		}
	}
}

sub report {
	my $cfghashref = shift;
	my $reshashref = shift;
	my $rpthashref = shift;

	logmsg(1, 0, "Ruuning report");
#	profile( whoami(), whowasi() );
	logmsg (5, 0, " and I was called by ... ".&whowasi);

	logmsg(5, 1, "Dump of results hash ...");
	Dumper(%$reshashref) if $DEBUG >= 5;

	print "\n\nNo match for lines:\n";
	foreach my $line (@{@$reshashref{nomatch}}) {
		print "\t$line";
	}
	print "\n\nSummaries:\n";
	for my $rule (sort keys %$reshashref)  {
		next if $rule =~ /nomatch/;
		if (exists ($$cfghashref{rules}{$rule}{rpttitle})) {
			print "$$cfghashref{rules}{$rule}{rpttitle}\n";
		} else {
			logmsg (4, 2, "Rule: $rule");
		}

		for my $key (keys %{$$reshashref{$rule}} )  {
			if (exists ($$cfghashref{rules}{$rule}{rptline})) {
				print "\t".rptline($cfghashref, $reshashref, $rpthashref, $rule, $key)."\n";
			} else {
				print "\t$$rpthashref{$rule}{$key}: $key\n";
			}
		}
		print "\n";
	}
}

sub rptline {
	my $cfghashref = shift;
	my $reshashref = shift;
	my $rpthashref = shift;
	my $rule = shift;
	my $key = shift;
	my $line = $$cfghashref{rules}{$rule}{rptline};

	# generate rpt line based on config spec for line and results.
	# Sample entry: {x}: logouts from {2} by {1}

#	profile( whoami(), whowasi() );
	logmsg (5, 2, " and I was called by ... ".&whowasi);
    logmsg (3, 2, "Starting with rule:$rule");
    logmsg (9, 3, "key: $key");
	my @fields = split /:/, $key;

    logmsg (9, 3, "line: $line");
    logmsg(9, 3, "subsituting {x} with $$rpthashref{$rule}{$key}{count}");
	$line =~ s/\{x\}/$$rpthashref{$rule}{$key}{count}/;
    
    if ($$cfghashref{rules}{$rule}{cmd} eq "SUM") {
	    $line =~ s/\{s\}/$$rpthashref{$rule}{$key}{sum}/;
    }
    if ($$cfghashref{rules}{$rule}{cmd} eq "AVG") {
        my $avg = $$rpthashref{$rule}{$key}{sum} / $$reshashref{$rule}{$key}{count};
        $avg = sprintf ("%.3f", $avg);
	    $line =~ s/\{a\}/$avg/;
    }

    logmsg (9, 3, "#fields ".($#fields+1)." in @fields");
	for my $i (0..$#fields) {
		my $field = $i+1;
        logmsg (9, 4, "$fields[$field] = $fields[$i]");
		if ($line =~ /\{$field\}/) {
			$line =~ s/\{$field\}/$fields[$i]/;
		}
	}
	return $line;
}

sub actionrule {
	# Collect data for rule $rule as defined in the ACTIONS section of %config
	 
	my $cfghashref = shift; # ref to $cfghash, would like to do $cfghash{rules}{$rule} but would break append
	my $reshashref = shift;
	my $rule = shift;
	my $line = shift; # hash passed by ref, DO NOT mod
	my $value;
	my $retval = 0; my $resultsrule;

#	profile( whoami(), whowasi() );
	logmsg (5, 0, " and I was called by ... ".&whowasi);
    logmsg (9, 2, "rule: $rule");

	if (exists ($$cfghashref{rules}{$rule}{appendrule})) {
	 $resultsrule = $$cfghashref{rules}{$rule}{appendrule};
	} else {
	 $resultsrule = $rule;
	}
	logmsg (5, 3, "rule: $rule");
    logmsg (5, 4, "results goto: $resultsrule");
    logmsg (5, 4, "cmdregex: $}{cmdregex}");
    logmsg (5, 4, "CMD negative regex: $$cfghashref{rules}{$rule}{cmdregexnegat}");
    logmsg (5, 4, "line: $$line{line}");
	if ($$cfghashref{rules}{$rule}{cmd} and $$cfghashref{rules}{$rule}{cmd} =~ /IGNORE/) {
        if (exists ($$cfghashref{rules}{$rule}{cmdregex}) ) {
		    if ($$cfghashref{rules}{$rule}{cmdregex} and $$line{line} =~  /$$cfghashref{rules}{$rule}{cmdregex}/ ) {
			    logmsg (5, 4, "rule $rule does matches and is a positive IGNORE rule");
            }
		} else {
			logmsg (5, 4, "rule $rule matches and is an IGNORE rule");
		    $retval = 1;
		}
    } elsif (exists ($$cfghashref{rules}{$rule}{cmdregex}) ) {
	    if ( not $$cfghashref{rules}{$rule}{cmdregexnegat} ) {
            if ( $$line{line}  =~  /$$cfghashref{rules}{$rule}{cmdregex}/ )  {
                logmsg (5, 4, "Positive match, calling actionrulecmd");
                actionrulecmd($cfghashref, $reshashref, $line, $rule, $resultsrule);
    		    $retval = 1;
            }
        } elsif ($$cfghashref{rules}{$rule}{cmdregexnegat}) {
            if ( $$line{line}  !~  /$$cfghashref{rules}{$rule}{cmdregex}/ ) {
                logmsg (5, 4, "Negative match, calling actionrulecmd");
                actionrulecmd($cfghashref, $reshashref, $line, $rule, $resultsrule);
    		    $retval = 1;
            }
        }
    } else {
        logmsg (5, 4, "No cmd regex, implicit match, calling actionrulecmd");
        actionrulecmd($cfghashref, $reshashref, $line, $rule, $resultsrule);
    	$retval = 1;
    }
    if ($retval == 0) {
		logmsg (5, 4, "line does not match cmdregex for rule: $rule");
	} 
	return $retval;
}
sub actionrulecmd
{
	my $cfghashref = shift;
	my $reshashref = shift;
	my $line = shift; # hash passed by ref, DO NOT mod
    my $rule = shift;
    my $resultsrule = shift;
#3	profile( whoami(), whowasi() );
	logmsg (5, 3, " and I was called by ... ".&whowasi);
    logmsg (2, 2, "actioning rule $rule for line: $$line{line}");

	# This sub contains the first half of the black magic
	# The results from the regex's that are applied later
	# are used in actioncmdmatrix()
	#
	
	# create a matrix that can be used for matching for the black magic happens
	# Instead of the string cmdmatrix
	# make a hash of matchmatrix{<match field#>} = <cmdregex field #>
	# 2 arrays ...
	#  fieldnums ... the <match field #'s> of matchmatrix{}
	#  fieldnames ... the named matches of matchmatrix{}, these match back to the names of the fields
	#    from the file FORMAT
	#
	my  @tmpmatrix = split (/,/, $$cfghashref{rules}{$rule}{cmdmatrix});
	my @matrix = ();
	for my $val (@tmpmatrix) {
		if ($val =~ /(\d+)/ ) {
			push @matrix, $val;
		} else {
			logmsg(3,3, "Not adding val:$val to matrix");
		}
	}
	logmsg(3, 3, "matrix: @matrix");
	#
	
    if (not $$cfghashref{rules}{$rule}{cmdregex}) {
        $$cfghashref{rules}{$rule}{cmdregex} = "(.*)";
	    logmsg (5, 3, "rule did not define cmdregex, replacing with global match");
    }
    if ( exists $$cfghashref{rules}{$rule}{cmd}) {
        logmsg (5, 3, "Collecting data from cmd $$cfghashref{rules}{$rule}{cmd}");
	    logmsg (5, 3, "rule $rule matches cmd") if $$line{msg}  =~ /$$cfghashref{rules}{$rule}{cmdregex}/;
    }

   if (not exists ($$cfghashref{rules}{$rule}{cmdregex}) ) {
        logmsg (5, 3, "No cmd regex, calling actioncmdmatrix");
        actioncmdmatrix($cfghashref, $reshashref, $line, $rule, $resultsrule, \@matrix);
    } elsif ($$cfghashref{rules}{$rule}{cmdregexnegat} ) {
        if ($$cfghashref{rules}{$rule}{cmdregex} and $$line{msg} and $$line{msg}  !~ /$$cfghashref{rules}{$rule}{cmdregex}/ ) {
            logmsg (5, 3, "Negative match, calling actioncmdmatrix");
            actioncmdmatrix($cfghashref, $reshashref, $line, $rule, $resultsrule, \@matrix);
        }
    } else {
        if ($$cfghashref{rules}{$rule}{cmdregex} and $$line{msg} and $$line{msg}  =~ /$$cfghashref{rules}{$rule}{cmdregex}/ ) {
            logmsg (5, 3, "Positive match, calling actioncmdmatrixnline hash:");
			print Dumper($line) if $DEBUG >= 5;
            actioncmdmatrix($cfghashref, $reshashref, $line, $rule, $resultsrule, \@matrix);
		} 
    } 
}

sub printhash
{
#	profile( whoami(), whowasi() );
	my $line = shift; # hash passed by ref, DO NOT mod
    foreach my $key (keys %{ $line} )
    {
        logmsg (9, 5, "$key: $$line{$key}");

    }
}

sub actioncmdmatrix
{
	my $cfghashref = shift;
	my $reshashref = shift;
	my $line = shift; # hash passed by ref, DO NOT mod
    my $rule = shift; # Name or ID of rule thats been matched
    my $resultsrule = shift; # Name or ID of rule which contains the result set to be updated
	my $matrixref = shift; # arrayref

	logmsg(5, 4, " ... actioning resultsrule = $rule");
	logmsg(5, 5, " and I was called by ... ".&whowasi);
	logmsg(9, 5, "Line hash ...");
	print Dumper(%$line);
	#profile( whoami(), whowasi() );
	my $cmdmatrix = $$cfghashref{rules}{$rule}{cmdmatrix};
	#my @matrix = shift; #split (/,/, $cmdmatrix);

	my $fieldhash;
	my $cmdfield;

	# @matrix - array of parameters that are used in results
	if ( exists ($$cfghashref{rules}{$rule}{cmdfield}) ) {
		$cmdfield = ${$$cfghashref{rules}{$rule}{cmdfield}};
	}
    
	if ( exists $$cfghashref{rules}{$rule}{cmdmatrix}) {
	    logmsg (5, 5, "Collecting data for matrix $$cfghashref{rules}{$rule}{cmdmatrix}");
	    print Dumper(@$matrixref);
	    logmsg (5, 5, "Using matrix @$matrixref");

		# this is where "strict refs" breaks things
		# sample: @matrix = svr,1,4,5
		# error ... can't use string ("svr") as a SCALAR ref while "strict refs" in use
		#

		# soln: create a temp array which only has the field #'s and match that
		# might need a hash to match

		no strict 'refs';	# turn strict refs off just for this section
		foreach my $field (@$matrixref) {
            # This is were the black magic occurs, ${$field} causes becomes $1 or $2 etc
            # and hence contains the various matches from the previous regex match
            # which occured just before this function was called

		    logmsg (9, 5, "matrix field $field has value ${$field}");
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
						logmsg (1, 6, "$field not found in \"$$line{line}\" with regex $$cfghashref{rules}{$rule}{cmdregex}");
						logmsg (1, 6, "line hash:");
                        print Dumper(%$line) if $DEBUG >= 1;
					}
				}
			}
		}

		use strict 'refs';
        if ($$cfghashref{rules}{$rule}{targetfield}) {
			logmsg (1, 5, "Setting cmdfield (field $$cfghashref{rules}{$rule}{targetfield}) to ${$$cfghashref{rules}{$rule}{targetfield}}");
            $cmdfield = ${$$cfghashref{rules}{$rule}{targetfield}};
        }
		#if ($$cfghashref{rules}{$rule}{cmd} and $$cfghashref{rules}{$rule}{cmd} =~ /^COUNT$/) { 
	    $$reshashref{$resultsrule}{$fieldhash}{count}++;
		logmsg (5, 5, "$$reshashref{$resultsrule}{$fieldhash}{count} matches for rule $rule so far from $fieldhash");
		#} els
        if ($$cfghashref{rules}{$rule}{cmd} eq "SUM" or $$cfghashref{rules}{$rule}{cmd} eq "AVG") { 
			$$reshashref{$resultsrule}{$fieldhash}{sum} = $$reshashref{$resultsrule}{$fieldhash}{sum} + $cmdfield;
			logmsg (5, 5, "Adding $cmdfield to total (now $$reshashref{$resultsrule}{$fieldhash}{sum}) for rule $rule so far from $fieldhash");
            if ($$cfghashref{rules}{$rule}{cmd} eq "AVG") {
			    logmsg (5, 5, "Average is ".$$reshashref{$resultsrule}{$fieldhash}{sum} / $$reshashref{$resultsrule}{$fieldhash}{count}." for rule $rule so far from $fieldhash");
            }
		}	
		for my $key (keys %{$$reshashref{$resultsrule}})  {
			logmsg (5, 5, "key $key for rule:$rule with $$reshashref{$resultsrule}{$key}{count} matches");
		}
		logmsg (5, 5, "$fieldhash matches for rule $rule so far from matrix: $$cfghashref{rules}{$rule}{cmdmatrix}");
	} else {
		logmsg (5, 5, "cmdmatrix is not set for $rule");
	    #if ($$cfghashref{rules}{$rule}{cmd} and $$cfghashref{rules}{$rule}{cmd} =~ /^COUNT$/) { 
			$$reshashref{$resultsrule}{count}++;
			logmsg (5, 5, "$$reshashref{$resultsrule}{count} lines match rule $rule so far");
	#	} els
        if ($$cfghashref{rules}{$rule}{cmd} eq "SUM" or $$cfghashref{rules}{$rule}{cmd} eq "AVG") { 
			$$reshashref{$resultsrule}{sum} = $$reshashref{$resultsrule}{sum} + $cmdfield;
			logmsg (5, 5, "$$reshashref{$resultsrule}{sum} lines match rule $rule so far");
		}
    }
    logmsg(5, 4, " ... Finished actioning resultsrule = $rule");
}

sub defaultregex {
	# expects a reference to the rule and param
	my $paramref = shift;
	logmsg(5, 4, " and I was called by ... ".&whowasi);
#	profile( whoami(), whowasi() );
	if (defined $$paramref[0]{regex} ) {
		logmsg(9, 4, "Skipping, there are already regex hashes in this rule/param match");
		logmsg(9, 5, "regex[0]regex = $$paramref[0]{regex}");
		logmsg(9, 5, "regex[0]negate = $$paramref[0]{negate}");
	} else {
		logmsg(9, 1, "There's no regex hash for this rule/param so setting defaults");
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
	logmsg(5, 3, " and I was called by ... ".&whowasi);
#	profile( whoami(), whowasi() );
	if ($value =~ /$$regex{regex}/ or  $$regex{regex} =~ /^\*$/ ) { 
		logmsg (9, 4, "value ($value) matches regex /$$regex{regex}/");
		$match = 1;
	} else {
		logmsg (9, 4, "value ($value) doesn't match regex /$$regex{regex}/");
	}
}

sub matchingrules {
	my $cfghashref = shift;
	my $param = shift;
	my $matchref = shift;
	my $value = shift;

	logmsg(5, 3, " and I was called by ... ".&whowasi);
	logmsg (6, 3, "param:$param");
	logmsg (6, 3, "value:$value");
    logmsg (3, 2, "$param, match count: ".keys(%{$matchref})." value: $value");

	if (keys %{$matchref} == 0) {
		# Check all rules as we haevn't had a match yet
		foreach my $rule (keys %{$cfghashref->{rules} } ) {
			checkrule($cfghashref, $param, $matchref, $rule, $value);
		}
	} else {
		# As we've allready had a match on the rules, only check those that matched in earlier rounds
		# key in %matches is the rule that matches
		foreach my $rule (keys %{$matchref}) {
			checkrule($cfghashref, $param, $matchref, $rule, $value);
		}
	}
}

sub checkrule {
	my $cfghashref = shift;
	my $param = shift;
	my $matches = shift;
	my $rule = shift; # key to %matches
	my $value = shift;

	logmsg(2, 1, "Checking rule ($rule) & param ($param) for matches against: $value");
	logmsg(5, 3, " and I was called by ... ".&whowasi);
	my $paramref = \@{ $$cfghashref{rules}{$rule}{$param} };
	defaultregex($paramref); # This should be done when reading the config

	foreach my $index (@{ $paramref } ) {
		my $match  = matchregex($index, $value);

		if ($$index{negate} ) {
			if ( $match) {
				delete $$matches{$rule};
				logmsg (5, 5, "matches $index->{regex} for param \'$param\', but negative rule is set, so removing rule $match from list.");
             } else {
				$$matches{$rule} = "match" if $match;
				logmsg (5, 5, "Doesn't match for $index->{regex} for param \'$param\', but negative rule is set, so leaving rule $match on list.");
             }
		} elsif ($match) {
			$$matches{$rule} = "match" if $match;
			logmsg (5, 4, "matches $index->{regex} for param \'$param\', leaving rule $match on list.");
		} else {
			delete $$matches{$rule};
			logmsg (5, 4, "doesn't match $index->{regex} for param \'$param\', removing rule $match from list.");
        }
	} # for each regex hash in the array
	logmsg (3, 2, "matches ".keys (%{$matches})." matches after checking rules for $param");
}

sub whoami  { (caller(1) )[3] }
sub whowasi { (caller(2) )[3] }

sub logmsg {
    my $level = shift;
    my $indent = shift;
    my $msg = shift;

    if ($DEBUG >= $level) {
        for my $i (0..$indent) {
            print STDERR "  ";
        }
        print STDERR whowasi."(): $msg\n";
    }
}

sub profile {
	my $caller = shift;
	my $parent = shift;

#	$profile{$parent}{$caller}++;
	
}

sub profilereport {
	print Dumper(%profile);
}

