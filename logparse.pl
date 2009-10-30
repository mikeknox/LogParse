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

=pod

=head1 logparse - syslog analysis tool

=head1 SYNOPSIS

./logparse.pl [-c <configfile> ] [-l <logfile>] [-d <debug level>]

=head1 Config file language description

This is a complete redefine of the language from v0.1 and includes some major syntax changes.
It was originally envisioned that it would be backwards compatible, but it won't be due to new requirements
such as adding OR operations 

=head3 Stanzas

The building block of this config file is the stanza which indicated by a pair of braces
<Type> [<label>] {
	# if label isn't declared, integer ID which autoincrements
}

There are 2 top level stanza types ...
 - FORMAT
  - doesn't need to be named, but if using multiple formats you should.
 - RULE


=head2 FORMAT stanza
=over
FORMAT <name> {
   DELIMITER <xyz>
   FIELDS <x>
   FIELD<x> <name>
}
=back
=cut

=head3 Parameters
[LASTLINE] <label> [<value>]
=item Parameters occur within stanza's.
=item labels are assumed to be field matches unless they are known commands
=item a parameter can have multiple values
=item the values for a parameter are whitespace delimited, but fields are contained by /<some text>/ or {<some text}
=item " ", / / & {  } define a single field which may contain whitespace
=item any field matches are by default AND'd together
=item multiple ACTION commands are applied in sequence, but are independent
=item multiple REPORT commands are applied in sequence, but are independent

- LASTLINE
 - Applies the field match or action to the previous line, rather than the current line
   - This means it would be possible to create configs which double count entries, this wouldn't be a good idea.

=head4 Known commands
These are labels which have a specific meaning. 
REPORT <title> <line>
ACTION <field> </regex/> <{matches}> <command> [<command specific fields>] [LASTLINE]
ACTION <field> </regex/> <{matches}> sum <{sum field}> [LASTLINE]
ACTION <field> </regex/> <{matches}> append <rule> <{field transformation}> [LASTLINE]

=head4 Action commands
 data for the actions are stored according to <{matches}>, so <{matches}> defines the unique combination of datapoints upon which any action is taken.
 - Ignore
 - Count  - Increment the running total for the rule for the set of <{matches}> by 1.
 - Sum - Add the value of the field <{sum field}> from the regex match to the running total for the set of <{matches}>
 - Append - Add the set of values <{matches}> to the results for rule <rule> according to the field layout described by <{field transformation}>
 - LASTLINE - Increment the {x} parameter (by <sum field> or 1) of the rules that were matched by the LASTLINE (LASTLINE is determined in the FORMAT stanza) 

=head3 Conventions
 regexes are written as / ... / or /! ... /
 /! ... / implies a negative match to the regex
 matches are written as { a, b, c } where a, b and c match to fields in the regex
 
=head1 Internal structures
=over
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
=back

=head1 BUGS:
	See http://github.com/mikeknox/LogParse/issues
=cut

# expects data on std in
use strict;
use Getopt::Std;
use Data::Dumper qw(Dumper);

# Globals
my %profile;
my $DEBUG = 0;
my %DEFAULTS = ("CONFIGFILE", "logparse.conf", "SYSLOGFILE", "/var/log/messages" );
my %opts;
my $CONFIGFILE="logparse.conf";
my %cfghash;
my %reshash;
my $UNMATCHEDLINES = 1;
my $SYSLOGFILE = "/var/log/messages";
my %svrlastline; # hash of the last line per server, excluding 'last message repeated x times'

getopt('cdl', \%opts);
$DEBUG = $opts{d} if $opts{d};
$CONFIGFILE = $opts{c} if $opts{c};
$SYSLOGFILE = $opts{l} if $opts{l};

loadcfg (\%cfghash, $CONFIGFILE);
print Dumper(\%cfghash);
processlogfile(\%cfghash, \%reshash, $SYSLOGFILE);
#report(\%cfghash, \%reshash);
#profilereport();

exit 0;

sub parselogline {
=head5 pareseline(\%cfghashref, $text, \%linehashref)
	
=cut
	my $cfghashref = shift;
	my $text = shift;
	my $linehashref = shift;
	logmsg(5, 3, " and I was called by ... ".&whowasi);
	logmsg(6, 4, "Text: $text");
	#@{$line{fields}} = split(/$$cfghashref{FORMAT}{ $format }{fields}{delimiter}/, $line{line}, $$cfghashref{FORMAT}{$format}{fields}{totalfields} );
	my @tmp;
	logmsg (6, 4, "delimiter: $$cfghashref{delimiter}");
	logmsg (6, 4, "totalfields: $$cfghashref{totalfields}");
	logmsg (6, 4, "defaultfield: $$cfghashref{defaultfield} ($$cfghashref{byindex}{ $$cfghashref{defaultfield} })") if exists ($$cfghashref{defaultfield}); 
	# if delimiter is not present and default field is set
	if ($text !~ /$$cfghashref{delimiter}/ and $$cfghashref{defaultfield}) {
		logmsg (5, 4, "\$text doesnot contain $$cfghashref{delimiter} and default of field $$cfghashref{defaultfield} is set, so assigning all of \$text to that field ($$cfghashref{byindex}{ $$cfghashref{defaultfield} })");
		$$linehashref{ $$cfghashref{byindex}{ $$cfghashref{defaultfield} } } = $text;
		if (exists($$cfghashref{ $$cfghashref{byindex}{ $$cfghashref{defaultfield} } } ) ) {
			logmsg(9, 4, "Recurisive call for field ($$cfghashref{default}) with text $text");
			parselogline(\%{ $$cfghashref{ $$cfghashref{defaultfield} } }, $text, $linehashref);
		}
	} else {
		(@tmp) = split (/$$cfghashref{delimiter}/, $text, $$cfghashref{totalfields});
	
		logmsg (9, 4, "Got field values ... ".Dumper(@tmp));
		for (my $i = 0; $i <= $#tmp+1; $i++) {
			$$linehashref{ $$cfghashref{byindex}{$i} } = $tmp[$i];
			logmsg(9, 4, "Checking field $i(".($i+1).")");
			if (exists($$cfghashref{$i + 1} ) ) {
				logmsg(9, 4, "Recurisive call for field $i(".($i+1).") with text $text");
				parselogline(\%{ $$cfghashref{$i + 1} }, $tmp[$i], $linehashref);
			}
		}
	}
	logmsg (9, 4, "line results now ...".Dumper($linehashref));
}

sub processlogfile {
	my $cfghashref = shift;
	my $reshashref = shift;
	my $logfile = shift;

	my $format = $$cfghashref{FORMAT}{default}; # TODO - make dynamic
	my %lastline;
	
	logmsg(1, 0, "processing $logfile using format $format...");
	logmsg(5, 1, " and I was called by ... ".&whowasi);
	open (LOGFILE, "<$logfile") or die "Unable to open $SYSLOGFILE for reading...";
	while (<LOGFILE>) {
		my $facility = "";
		my %line;
		# Placing line and line componenents into a hash to be passed to actrule, components can then be refered
		# to in action lines, ie {svr} instead of trying to create regexs to collect individual bits
		$line{line} = $_;

    	logmsg(5, 1, "Processing next line");
    	logmsg(9, 2, "Delimiter: $$cfghashref{FORMAT}{ $format }{fields}{delimiter}");
    	logmsg(9, 2, "totalfields: $$cfghashref{FORMAT}{$format}{fields}{totalfields}");
    	#@{$line{fields}} = split(/$$cfghashref{FORMAT}{ $format }{fields}{delimiter}/, $line{line}, $$cfghashref{FORMAT}{$format}{fields}{totalfields} );
    	parselogline(\%{ $$cfghashref{FORMAT}{$format}{fields} }, $line{line}, \%line);
    	
		#($line{mth}, $line{date}, $line{time}, $line{svr}, $line{app}, $line{msg}) = split (/\s+/, $line{line}, 6);
#		logmsg(9, 2, "mth: $line{mth}, date: $line{date}, time: $line{time}, svr: $line{svr}, app: $line{app}, msg: $line{msg}");
		logmsg(9, 1, "Checking line: $line{line}");
		logmsg(9, 2, "Extracted Field contents ...\n".Dumper(@{$line{fields}}));
		
		my %rules = matchrules(\%{ $$cfghashref{RULE} }, \%line );
#		my %matchregex = ("svrregex", "svr", "appregex", "app", "facregex", "facility", "msgregex", "line");
#		for my $field (keys %{$$cfghashref{formats}{$format}{fields}{byname} }) {
#			matchingrules($cfghashref, $field, \%matches, $line{ $field } );
#		}
		###matchingrules($cfghashref, $param, \%matches, $line{ $matchregex{$param} } );
		#}
		logmsg(9, 2, keys (%rules)." matches so far");
		$$reshashref{nomatch}[$#{$$reshashref{nomatch}}+1] = $line{line} and next unless keys(%rules) > 0;
		logmsg(9,1,"Results hash ...".Dumper(%$reshashref) );
#TODO Handle "Message repeated" type scenarios when we don't know which field should contatin the msg
#UP to here	
		# FORMAT stanza contains a substanza which describes repeat for the given format
		# format{repeat}{cmd} - normally regex, not sure what other solutions would apply
		# format{repeat}{regex} - array of regex's hashes
		# format{repeat}{field} - the name of the field to apply the cmd (normally regex) to
		
		#TODO describe matching of multiple fields ie in syslog we want to match regex and also ensure that HOST matches previous previousline
		# Detect and count repeats
=replace with repeat rule
		if ( exists( $$cfghashref{formats}{$format}{repeat} ) ) {
			my $repeatref = \%{$$cfghashref{formats}{$format}{repeat} };
			if ($$repeatref{cmd} =~ /REGEX/ ) {
				foreach my $i (@{$$repeatref{regex}}) {
					if ($line{$$repeatref{field}} =~ /$$repeatref{regex}[$i]{regex}/) {
						
					}
				}
			}
		}

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
=cut
	    	if (keys %rules > 0) {
#dep				logmsg (5, 2, "svr & app & fac & msg matched rules: ");
				logmsg (5, 2, "matched ".keys(%rules)." rules from line $line{line}");

		    	# loop through matching rules and collect data as defined in the ACTIONS section of %config
		    	my $actrule = 0;
            	my %tmprules = %rules;
		    	for my $rule (keys %tmprules) {
		    		logmsg (9, 3, "checking rule: $rule");
			    	delete $rules{$rule} unless actionrule(\%{ $$cfghashref{RULE} }, $reshashref, $rule, \%line);
			 # TODO: update &actionrule();
                	 #unless $result ;
                	#$actrule = $result unless $actrule;
#dep			    	logmsg (5, 3, "Applying cmds for rule $rule, as passed prelim regexes");
#dep                	logmsg (10, 4, "an action rule matched: $actrule");
		    	}
#dep            	logmsg (10, 4, "an action rule matched: $actrule");
		    	$$reshashref{nomatch}[$#{$$reshashref{nomatch}}+1] = $line{line} if keys(%rules) == 0;
		    # HERE
		    # lastline & repeat
	    	} # rules > 0
=dep
# now handled in action rules		    
            	%{$svrlastline{$line{svr} }{rulematches}} = %matches unless ($line{msg} =~ /last message repeated d+ times/);

            	logmsg (5, 2, "setting lastline match for server: $line{svr} and line:\n$line{line}");
				logmsg (5, 3, "added matches for $line{svr} for rules:");
				for my $key (keys %{$svrlastline{$line{svr} }{rulematches}}) {
		        	logmsg (5, 4, "$key");
            	}
=cut
#dep				logmsg (5, 3, "rules from line $line{line}");
			if (exists( $lastline{ $line{ $$cfghashref{FORMAT}{$format}{LASTLINEINDEX} } } ) ) {
				delete ($lastline{ $line{ $$cfghashref{FORMAT}{$format}{LASTLINEINDEX} } });
			}
			$lastline{ $line{ $$cfghashref{FORMAT}{$format}{LASTLINEINDEX} } } = %line;

			if ( keys(%rules) == 0) {
				# Add new unmatched linescode				
			}
=dep
        	#} else {
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
=cut
    	logmsg (5, 1, "finished processing line");
		}
=does this segment need to be rewritten or depricated?
	foreach my $server (keys %svrlastline) {
   		if ( $svrlastline{$server}{unmatchedline}{count} >= 1) {
       		logmsg (9, 2, "Added record #".( $#{$$reshashref{nomatch}} + 1 )." for unmatched results");
    		$$reshashref{nomatch}[$#{$$reshashref{nomatch}}+1] = "$server: Last unmatched message repeated $svrlastline{$server }{unmatchedline}{count} timesn";
		}
	}
=cut
	logmsg (1, 0, "Finished processing $logfile.");
}

sub getparameter {
=head6 getparamter($line)
returns array of line elements
lines are whitespace delimited, except when contained within " ", {} or //
=cut
	my $line = shift;
	logmsg (5, 3, " and I was called by ... ".&whowasi);
	
	chomp $line;
	logmsg (9, 5, "passed $line");
	my @A;
	if ($line =~ /^#|^\s+#/ ) {
		logmsg(9, 4, "comment line, skipping, therefore returns are empty strings");
	} elsif ($line =~ /^\s+$/ or $line =~ /^$/ ){
		logmsg(9, 4, "empty line, skipping, therefore returns are empty strings");
	} else {
		$line =~ s/#.*$//; # strip anything after #
		#$line =~ s/{.*?$//; # strip trail {, it was required in old format
		@A =  $line =~ /(\/.+?\/|\{.+?\}|".+?"|\S+)/g;
	}
	for (my $i = 0; $i <= $#A; $i++ ) {
		logmsg (9, 5, "\$A[$i] is $A[$i]");
		# Strip any leading or trailing //, {}, or "" from the fields
		$A[$i] =~ s/^(\"|\/|{)//;
		$A[$i] =~ s/(\"|\/|})$//;
		logmsg (9, 5, "$A[$i] has had the leading \" removed");	
	}
	logmsg (9, 5, "returning @A");
	return @A;
}

sub parsecfgline {
=head6 parsecfgline($line)
Depricated, use getparameter()
takes line as arg, and returns array of cmd and value (arg)
=cut
	my $line = shift;

	logmsg (5, 3, " and I was called by ... ".&whowasi);
	my $cmd = "";
	my $arg = "";
	chomp $line;

	logmsg(5, 3, " and I was called by ... ".&whowasi);
	logmsg (6, 4, "line: ${line}");

	if ($line =~ /^#|^\s+#/ ) {
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
=head6 loadcfg(<cfghashref>, <cfgfile name>)
	Load cfg loads the config file into the config hash, which it is passed as a ref.
	
	loop through the logfile
	- skip any lines that only contain comments or whitespace
	- strip any comments and whitespace off the ends of lines
	- if a RULE or FORMAT stanza starts, determine the name
	- if in a RULE or FORMAT stanza pass any subsequent lines to the relevant parsing subroutine.
	- brace counts are used to determine whether we've finished a stanza	
=cut
	my $cfghashref = shift;
	my $cfgfile = shift;

	open (CFGFILE, "<$cfgfile");

	logmsg(1, 0, "Loading cfg from $cfgfile");
	logmsg(5, 3, " and I was called by ... ".&whowasi);
	
	my $rulename = -1;
	my $ruleid = 0;
	my $stanzatype = "";

	while (<CFGFILE>) {
		my $line = $_;

		logmsg(5, 1, "line: $line");
		logmsg(6, 2, "stanzatype:$stanzatype ruleid:$ruleid rulename:$rulename");

		my @args = getparameter($line);
		next unless $args[0];
		logmsg(6, 2, "line parameters: @args");

 		for ($args[0]) {
  			if (/RULE|FORMAT/) {
  				$stanzatype=$args[0];
   				if ($args[1] and $args[1] !~ /\{/) {
    				$rulename = $args[1];
					logmsg(9, 3, "rule (if) is now: $rulename");
   				} else {
    				$rulename = $ruleid++;
					logmsg(9, 3, "rule (else) is now: $rulename");
   				} # if arg
   				$$cfghashref{$stanzatype}{$rulename}{name}=$rulename; # setting so we can get name later from the sub hash
				unless (exists $$cfghashref{FORMAT}) {
					logmsg(0, 0, "Aborted. Error, rule encounted before format defined.");
					exit 2;
				}
				
				logmsg(6, 2, "stanzatype updated to: $stanzatype");
				logmsg(6, 2, "rule updated to:$rulename");
			} elsif (/FIELDS/) {
				fieldbasics(\%{ $$cfghashref{$stanzatype}{$rulename}{fields} }, \@args);
			} elsif (/FIELD$/) {
				fieldindex(\%{ $$cfghashref{$stanzatype}{$rulename}{fields} }, \@args);
			} elsif (/DEFAULT/) {
				$$cfghashref{$stanzatype}{$rulename}{default} = 1;
				$$cfghashref{$stanzatype}{default} = $rulename;				
			} elsif (/LASTLINEINDEX/) {
				$$cfghashref{$stanzatype}{$rulename}{LASTLINEINDEX} = $args[1];
			} elsif (/ACTION/) {
				logmsg(9, 5, "stanzatype: $stanzatype rulename:$rulename");			
				setaction(\@{ $$cfghashref{$stanzatype}{$rulename}{actions} }, \@args);
			} elsif (/REPORT/) {
				setreport(\@{ $$cfghashref{$stanzatype}{$rulename}{reports} }, \@args);
			} else {
				# Assume to be a match
				$$cfghashref{$stanzatype}{$rulename}{fields}{$args[0]} = $args[1];		
			}# if cmd
		} # for cmd
	} # while
	close CFGFILE;
	logmsg (5, 1, "Config Hash contents:");
	&Dumper( %$cfghashref );
	logmsg (1, 0, "finished processing cfg: $cfgfile");
} # sub loadcfg

sub setaction {
=head6 setaction ($cfghasref, @args)
where cfghashref should be a reference to the action entry for the rule
sample
ACTION MSG /(.*): TTY=(.*) ; PWD=(.*); USER=(.*); COMMAND=(.*)/ {HOST, 1, 4, 5} count
=cut

	my $actionref = shift;
	my $argsref = shift;

	logmsg (5, 4, " and I was called by ... ".&whowasi);
	logmsg (6, 5, "args: ".Dumper(@$argsref));
	
	logmsg (9, 5, "args: $$argsref[2]");
	unless (exists ${@$actionref}[0] ) {
		logmsg(9, 3, "actions array, doesn't exist, initialising");
		@$actionref = ();
	}
	my $actionindex = $#{ @$actionref } + 1;
	logmsg(9, 3, "actionindex: $actionindex");
# ACTION formats:
#ACTION <field> </regex/> [<{matches}>] <command> [<command specific fields>] [LASTLINE]
#ACTION <field> </regex/> <{matches}> <sum|count> [<{sum field}>] [LASTLINE]
#ACTION <field> </regex/> <{matches}> append <rule> <{field transformation}> [LASTLINE]
# count - 4 or 5
# sum - 5 or 6
# append - 6 or 7

	$$actionref[$actionindex]{field} = $$argsref[1];
	$$actionref[$actionindex]{regex} = $$argsref[2];
	if ($$argsref[3] =~ /count/i) {
		$$actionref[$actionindex]{cmd} = $$argsref[3];
	} else {
		$$actionref[$actionindex]{matches} = $$argsref[3];
		$$actionref[$actionindex]{cmd} = $$argsref[4];	
	}
	for ($$argsref[4]) {
		if (/^sum$/i) {
			$$actionref[$actionindex]{sourcefield} = $$argsref[5];
		} elsif (/^append$/i) {
			$$actionref[$actionindex]{appendtorule} = $$argsref[5];
			$$actionref[$actionindex]{fieldmap} = $$argsref[6];
		} else {
			logmsg (1,0, "WARNING, unrecognised command ($$argsref[4]) in ACTION command");
		}
	}
	my @tmp = grep /^LASTLINE$/i, @$argsref;
	if ($#tmp) {
		$$actionref[$actionindex]{lastline} = 1; 
	}
	
	$$actionref[$actionindex]{cmd} = $$argsref[4];
}

sub setreport {
=head6 fieldbasics ($cfghasref, @args)
where cfghashref should be a reference to the fields entry for the rule
REPORT "Sudo Usage" "{2} ran {4} as {3} on {1}: {x} times"
=cut

	my $reportref = shift;
	my $argsref = shift;

	logmsg (5, 4, " and I was called by ... ".&whowasi);
	logmsg (6, 5, "args: ".Dumper(@$argsref));
	logmsg (9, 5, "args: $$argsref[2]");
	
	unless (exists ${@$reportref}[0] ) {
		logmsg(9, 3, "report array, doesn't exist, initialising");
		@$reportref = ();
	}
	
	my $reportindex = $#{ @$reportref } + 1;
	logmsg(9, 3, "reportindex: $reportindex");
	
	$$reportref[$reportindex]{title} = $$argsref[1];
	$$reportref[$reportindex]{line} = $$argsref[2];
}
sub fieldbasics {
=head6 fieldbasics ($cfghasref, @args)
where cfghashref should be a reference to the fields entry for the rule
Creates the recursive index listing for fields
Passed @args - array of entires for config line
format

FIELDS 6-2 /]\s+/
or
FIELDS 6 /\w+/
=cut

	my $cfghashref = shift;
	my $argsref = shift;

	logmsg (5, 4, " and I was called by ... ".&whowasi);
	logmsg (6, 5, "args: ".Dumper(@$argsref));
	logmsg (9, 5, "fieldindex: $$argsref[1] fieldname $$argsref[2]");
	logmsg (9, 5, "fieldcount: $$argsref[1]");
	if ($$argsref[1] =~ /^(\d+)-(.*)$/ ) {
		# this is an infinite loop, need to rectify
		logmsg (6, 5, "recursive call using $1");
		$$argsref[1] = $2;
		logmsg (9, 5, "Updated fieldcount to: $$argsref[1]");
		logmsg (9, 5, "Calling myself again using hashref{fields}{$1}");
		fieldbasics(\%{ $$cfghashref{$1} }, $argsref);
	} else {
		$$cfghashref{delimiter} = $$argsref[2];
		$$cfghashref{totalfields} = $$argsref[1];
		for my $i(0..$$cfghashref{totalfields} - 1 ) {
			$$cfghashref{byindex}{$i} = "$i"; # map index to name
			$$cfghashref{byname}{$i} = "$i"; # map name to index
		}
	}
}

sub fieldindex {
=head6 fieldindex ($cfghasref, @args)
where cfghashref should be a reference to the fields entry for the rule
Creates the recursive index listing for fields
Passed @args - array of entires for config line
=cut

	my $cfghashref = shift;
	my $argsref = shift;

	logmsg (5, 4, " and I was called by ... ".&whowasi);
	logmsg (6, 5, "args: ".Dumper(@$argsref));
	logmsg (9, 5, "fieldindex: $$argsref[1] fieldname $$argsref[2]");
	if ($$argsref[1] =~ /^(\d+)-(.*)$/ ) {
		# this is an infinite loop, need to rectify
		logmsg (6, 5, "recursive call using $1");
		$$argsref[1] = $2;
		fieldindex(\%{ $$cfghashref{$1} }, $argsref);
	} else {
		$$cfghashref{byindex}{$$argsref[1]-1} = $$argsref[2]; # map index to name
		$$cfghashref{byname}{$$argsref[2]} = $$argsref[1]-1; # map name to index
		if (exists( $$cfghashref{byname}{$$argsref[1]-1} ) )  {
			delete( $$cfghashref{byname}{$$argsref[1]-1} );
		}		
	}
	my @tmp = grep /^DEFAULT$/i, @$argsref;
	if ($#tmp) {
		$$cfghashref{defaultfield} = $$argsref[1]; 
	}		
}

=obsolete
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
				&Dumper( %$cfghashref ) if $DEBUG >= 9;
			} elsif (/FIELDS/) {
				$$cfghashref{totalfields} = $arg;
				for my $i(1..$$cfghashref{totalfields}) {
					$$cfghashref{fields}{byindex}{$i} = "$i"; # map index to name
					$$cfghashref{fields}{byname}{$i} = "$i"; # map name to index
				}
			} elsif (/FIELD(\d+)/) {
				logmsg(6, 6, "FIELD#: $1 arg:$arg");
				$$cfghashref{fields}{byindex}{$1} = "$arg"; # map index to name
				$$cfghashref{fields}{byname}{$arg} = "$1"; # map name to index
				if (exists($$cfghashref{fields}{byname}{$1}) ) {
					delete($$cfghashref{fields}{byname}{$1});
				}
			} elsif (/DEFAULT/) {
				$$cfghashref{default} = 1;
			#} elsif (/REPEAT/) {
#TODO Define sub stanzas, it's currently hacked in
			#	extractcmd(\%{$$cfghashref{repeat}}, $cmd, "repeat", $arg);0
			} elsif (/REGEX/) {
				extractcmd(\%{$$cfghashref{repeat}}, $cmd, "regex", $arg);
			} elsif (/FIELD/) {
				$$cfghashref{repeat}{field} = $arg;
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
	my $forhashref = shift; # ref to log format hash
	my $cmd = shift;
	my $arg = shift;

	#profile( whoami(), whowasi() );
	logmsg (5, 4, " and I was called by ... ".&whowasi);
	logmsg (5, 4, "Processing $$cfghashref{name} with cmd: $cmd and arg: $arg");

	logmsg (5, 5, "Format hash ...".Dumper(%$forhashref) );
	next unless $cmd;
	for ($cmd) {
   # Static parameters
   		if (/FORMAT/){
   			# This really should be the first entry in a rule stanza if it's set
   			$$cfghashref{format} = $arg;
   		} elsif (/CMD/) {
    		extractcmd($cfghashref, $cmd, "cmd", $arg);
  		} elsif (/^REGEX/) {
    		extractcmd($cfghashref, $cmd, "regex", $arg);
		} elsif (/MATCH/) {
			extractcmd($cfghashref, $cmd, "matrix", $arg);
  		} elsif (/IGNORE/) {
   			extractcmd(\%{$$cfghashref{CMD}}, $cmd, "", $arg);
  		} elsif (/COUNT/) {
   			extractcmd(\%{$$cfghashref{CMD}}, $cmd, "", $arg);
  		} elsif (/SUM/) {
   			extractcmd(\%{$$cfghashref{CMD}}, $cmd, "targetfield", $arg);
  		} elsif (/AVG/) {
  			extractcmd(\%{$$cfghashref{CMD}}, $cmd, "targetfield", $arg);
  		} elsif (/TITLE/) {
   			$$cfghashref{RPT}{title} = $arg;
   			$$cfghashref{RPT}{title} = $1 if $$cfghashref{RPT}{title} =~ /^\"(.*)\"$/;
  		} elsif (/LINE/) {
   			$$cfghashref{RPT}{line} = $arg;
   			$$cfghashref{RPT}{line} = $1 if $$cfghashref{RPT}{line} =~ /\^"(.*)\"$/;
  		} elsif (/APPEND/) {
   			$$cfghashref{RPT}{appendrule} = $arg;
   			logmsg (1, 0, "*** Setting append for $$cfghashref{name} to $arg");
  		} elsif (/REPORT/) {
  		} elsif (/^\}$/) {
  		} elsif (/^\{$/) {
# Dynamic parameters (defined in FORMAT stanza)
  		} elsif (exists($$forhashref{fields}{byname}{$cmd} ) ) {
  			extractregex (\%{$$cfghashref{fields} }, $cmd, $arg);	
# End Dynamic parameters
  		} else {
    		print "Error: $cmd didn't match any known fields\n\n";
  		}
	} # for
    logmsg (5, 1,  "Finished processing rule: $$cfghashref{name}");
	logmsg (9, 1, "Config hash after running processrule");
	Dumper(%$cfghashref);
} # sub processrule
=cut
=obsolete?
sub extractcmd {		
	my $cfghashref = shift;
	my $cmd = shift;
	my $param = shift; # The activity associated with cmd
	my $arg = shift; # The value for param
	
	if ($param) {
		extractregex ($cfghashref, "$param", $arg);
   		$$cfghashref{$param} =~ s/\s+//g; # strip all whitespace		
	}	

   	$$cfghashref{cmd} = $cmd;
}
			
sub extractregexold {
	# Keep the old behaviour
	my $cfghashref = shift;
    my $param = shift;
    my $arg = shift;

#	profile( whoami(), whowasi() );
	logmsg (5, 3, " and I was called by ... ".&whowasi);
	my $paramnegat = $param."negate";

    logmsg (5, 1, "rule: $$cfghashref{name} param: $param arg: $arg");
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

	my $index = 0;

#	profile( whoami(), whowasi() );
	logmsg (5, 3, " and I was called by ... ".&whowasi);
	logmsg (1, 3, " rule: $$cfghashref{name} for param $param with arg $arg ");
	#TODO {name} is null when called for sub stanzas such as CMD or REPEAT, causes an "uninitialised value" warning
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
=cut
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

sub getmatchlist {
	# given a match field, return 2 lists
	# list 1: all fields in that list
	# list 2: only numeric fields in the list
	
	my $matchlist = shift;
	my $numericonly = shift;
	
	my @matrix = split (/,/, $matchlist);
    if ($matchlist !~ /,/) {
    	push @matrix, $matchlist;
    }
    my @tmpmatrix = ();
    for my $i (0 .. $#matrix) {
    	$matrix[$i] =~ s/\s+//g;
    	if ($matrix[$i] =~ /\d+/) {
    		push @tmpmatrix, $matrix[$i];
    	}
    }
    
    if ($numericonly) {
    	return @tmpmatrix;
    } else {
    	return @matrix;
    }
}
sub actionrule {
	# Collect data for rule $rule as defined in the ACTIONS section of %config
	# returns 0 if unable to apply rule, else returns 1 (success)
	# use ... actionrule($cfghashref{RULE}, $reshashref, $rule, \%line);	 
	my $cfghashref = shift; # ref to $cfghash, would like to do $cfghash{RULES}{$rule} but would break append
	my $reshashref = shift;
	my $rule = shift;
	my $line = shift; # hash passed by ref, DO NOT mod
#	my $retvalue;
	my $retval = 0;
	#my $resultsrule;

	logmsg (5, 1, " and I was called by ... ".&whowasi);
    logmsg (6, 2, "rule: $rule called for $$line{line}");
    
    logmsg (9, 3, ($#{ $$cfghashref{$rule}{actions} } + 1)." actions for rule: $rule");
    for my $actionid ( 0 .. $#{ $$cfghashref{$rule}{actions} } ) {
    	logmsg (6, 2, "Actionid: $actionid");
    	# actionid needs to recorded in resultsref as well as ruleid

		my @matrix = getmatchlist($$cfghashref{$rule}{actions}[$actionid]{matches}, 0);
		my @tmpmatrix = getmatchlist($$cfghashref{$rule}{actions}[$actionid]{matches}, 1); 

    	logmsg (9, 4, ($#tmpmatrix + 1)." entries for matching, using list @tmpmatrix");
   		my $matchid;
   		my @resmatrix = ();
    	no strict;
    	if ($$cfghashref{$rule}{actions}[$actionid]{regex} =~ /^\!/) {
    		my $regex = $$cfghashref{$rule}{actions}[$actionid]{regex};
    		$regex =~ s/^!//; 
    		if ($$line{ $$cfghashref{$rule}{actions}[$actionid]{field} } !~ /$regex/ ) {
				for my $val (@tmpmatrix) {
					push @resmatrix, ${$val};
					logmsg (9,5, "Adding ${$val} (from match: $val) to matrix");
				}
				$matchid = populatematrix(\@resmatrix, $$cfghashref{$rule}{actions}[$actionid]{matches}, $line);
				$retvalue = 1;
    		}
    	} else {	
    		if ($$line{ $$cfghashref{$rule}{actions}[$actionid]{field} } =~ /$$cfghashref{$rule}{actions}[$actionid]{regex}/ ) {
				for my $val (@tmpmatrix) {
					push @resmatrix, ${$val};
					logmsg (9,5, "Adding ${$val} (from match: $val) to matrix");
				}
				$matchid = populatematrix(\@resmatrix, $$cfghashref{$rule}{actions}[$actionid]{matches}, $line);
				$retval = 1;
    		}
    		logmsg(6, 3, "matrix for $rule & actionid $actionid: @matrix & matchid $matchid");
    	}
    	use strict;
    	if ($matchid) {
    		for ($$cfghashref{$rule}{actions}[$actionid]{cmd}) {
    			if (/sum/) {
    				$$reshashref{$rule}{$actionid}{$matchid} += $resmatrix[ $$cfghashref{$rule}{actions}[$actionid]{sourcefield} ];
    			} elsif (/count/) {
    				$$reshashref{$rule}{$actionid}{$matchid}++;	
    			} elsif (/append/) {
    				
    			} else {
    				logmsg (1, 0, "Warning: unfrecognized cmd ($$cfghashref{$rule}{actions}[$actionid]{cmd}) in action ($actionid) for rule: $rule");
    			}
    		}
    	}
    }
    logmsg (7, 5, "\%reshash ...".Dumper($reshashref));
    
    return $retval;
}

sub populatematrix {
	#my $cfghashref = shift; # ref to $cfghash, would like to do $cfghash{RULES}{$rule} but would break append
	#my $reshashref = shift;
	my $resmatrixref = shift;
	my $matchlist = shift;
	my $lineref = shift; # hash passed by ref, DO NOT mod
	my $matchid;
	
	logmsg (9, 5, "\@resmatrix ... ".Dumper($resmatrixref) );
	
	my @matrix = getmatchlist($matchlist, 0);
	my @tmpmatrix = getmatchlist($matchlist, 1); 
	logmsg (9, 6, "\@matrix ..".Dumper(@matrix));
	logmsg (9, 6, "\@tmpmatrix ..".Dumper(@tmpmatrix));
	
	my $tmpcount = 0;
	for my $i (0 .. $#matrix) {
		logmsg (9, 5, "Getting value for field \@matrix[$i] ... $matrix[$i]");
		if ($matrix[$i] =~ /\d+/) {
			#$matrix[$i] =~ s/\s+$//;
			$matchid .= ":".$$resmatrixref[$tmpcount];
			$matchid =~ s/\s+$//g;
			logmsg (9, 6, "Adding \@resmatrix[$tmpcount] which is $$resmatrixref[$tmpcount]");
			$tmpcount++;
		} else {
			$matchid .= ":".$$lineref{ $matrix[$i] };
			logmsg (9, 6, "Adding \%lineref{ $matrix[$i]} which is $$lineref{$matrix[$i]}");
		}
	}
	$matchid =~ s/^://; # remove leading :
	logmsg (6, 4, "Got matchid: $matchid");
	
	return $matchid;	
}

=depricate
sub actionrule {
	# Collect data for rule $rule as defined in the ACTIONS section of %config
	# returns 0 if unable to apply rule, else returns 1 (success)
	 
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
	
	unless ($$cfghashref{rules}{cmdregex}) {
		$$cfghashref{rules}{cmdregex} = "";
	}
	logmsg (5, 3, "rule: $rule");
    logmsg (5, 4, "results goto: $resultsrule");
    logmsg (5, 4, "cmdregex: $$cfghashref{rules}{cmdregex}");
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
=cut
=depricate
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
=cut

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
	
	# An empty or null $value = no match
	logmsg(5, 3, " and I was called by ... ".&whowasi);
#	profile( whoami(), whowasi() );
	logmsg(6, 4, "Does value($value) match regex /$$regex{regex}/");
	if ($value) {
		if ($value =~ /$$regex{regex}/ or  $$regex{regex} =~ /^\*$/ ) { 
			logmsg (9, 4, "value ($value) matches regex /$$regex{regex}/");
			$match = 1;
		} else {
			logmsg (9, 4, "value ($value) doesn't match regex /$$regex{regex}/");
		}
	} else {
		logmsg(7, 5, "\$value is null, no match");
	}
}

sub matchrules {
	my $cfghashref = shift;
	my $linehashref = shift;
	# loops through the rules and calls matchfield for each rule
	# assumes cfghashref{RULE} has been passed
	# returns a list of matching rules
	
	my %rules;	
	for my $rule (keys %{ $cfghashref } ) {
		$rules{$rule} = $rule if matchfields(\%{ $$cfghashref{$rule}{fields} } , $linehashref); 
	}
	
	return %rules;
}

sub matchfields {
	my $cfghashref = shift; # expects to be passed $$cfghashref{RULES}{$rule}{fields}
	my $linehashref = shift;
	
	my $ret = 1;
	# Assume fields match.
	# Only fail if a field doesn't match.
	# Passed a cfghashref to a rule
	
	foreach my $field (keys (%{ $cfghashref } ) ) {
		if ($$cfghashref{fields}{$field} =~ /^!/) {
			my $exp = $$cfghashref{fields}{$field};
			$exp =~ s/^\!//;
			$ret = 0 unless ($$linehashref{ $field } !~ /$exp/);		
		} else {
			$ret = 0 unless ($$linehashref{ $field } =~ /$$cfghashref{fields}{$field}/);
		}
	}
	return $ret;
}

sub matchingrules {
	my $cfghashref = shift;
	my $param = shift;
	my $matchref = shift;
	my $value = shift;

	logmsg(5, 3, " and I was called by ... ".&whowasi);
	logmsg (6, 3, "param:$param");
	logmsg (6, 3, "value:$value") if $value;
    logmsg (3, 2, "$param, match count: ".keys(%{$matchref}) );

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

