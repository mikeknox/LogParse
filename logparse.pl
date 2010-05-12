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
use Getopt::Long;
use Data::Dumper qw(Dumper);

# Globals
#
my $STARTTIME = time();
my %profile;
my $DEBUG = 0;
my %DEFAULTS = ("CONFIGFILE", "logparse.conf", "SYSLOGFILE", "/var/log/messages" );
my %opts;
my @CONFIGFILES;# = ("logparse.conf");
my %cfghash;
my %reshash;
my $UNMATCHEDLINES = 1;
my @LOGFILES;
my %svrlastline; # hash of the last line per server, excluding 'last message repeated x times'
my $MATCH; # Only lines matching this regex will be parsed
my $COLOR = 0;

my $result = GetOptions("c|conf=s" => \@CONFIGFILES,
					"l|log=s" => \@LOGFILES,
					"d|debug=i" => \$DEBUG,
					"m|match=s" => \$MATCH,
					"color" => \$COLOR
		);

unless ($result) {
	warning ("c", "Usage: logparse.pl -c <config file> -l <log file> [-d <debug level>] [--color]\nInvalid  config options passed");
}

if ($COLOR) {
	use Term::ANSIColor qw(:constants);
}

@CONFIGFILES = split(/,/,join(',',@CONFIGFILES));
@LOGFILES = split(/,/,join(',',@LOGFILES));
if ($MATCH) {
	$MATCH =~ s/\^\"//;
	$MATCH =~ s/\"$//;
	logmsg (2, 3, "Skipping lines which match $MATCH");
}

loadcfg (\%cfghash, \@CONFIGFILES);
logmsg(7, 3, "cfghash:", \%cfghash);
processlogfile(\%cfghash, \%reshash, \@LOGFILES);
logmsg (9, 0, "reshash ..\n", %reshash);
report(\%cfghash, \%reshash);

logmsg (9, 0, "reshash ..\n", %reshash);
logmsg (9, 0, "cfghash ..\n", %cfghash);


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
		logmsg (5, 4, "\$text does not contain $$cfghashref{delimiter} and default of field $$cfghashref{defaultfield} is set, so assigning all of \$text to that field ($$cfghashref{byindex}{ $$cfghashref{defaultfield} })");
		$$linehashref{ $$cfghashref{byindex}{ $$cfghashref{defaultfield} } } = $text;
		if (exists($$cfghashref{ $$cfghashref{byindex}{ $$cfghashref{defaultfield} } } ) ) {
			logmsg(9, 4, "Recurisive call for field ($$cfghashref{default}) with text $text");
			parselogline(\%{ $$cfghashref{ $$cfghashref{defaultfield} } }, $text, $linehashref);
		}
	} else {
		(@tmp) = split (/$$cfghashref{delimiter}/, $text, $$cfghashref{totalfields});
	
		logmsg (9, 4, "Got field values ... ", \@tmp);
		for (my $i = 0; $i <= $#tmp+1; $i++) {
			$$linehashref{ $$cfghashref{byindex}{$i} } = $tmp[$i];
			logmsg(9, 4, "Checking field $i(".($i+1).")");
			if (exists($$cfghashref{$i + 1} ) ) {
				logmsg(9, 4, "Recurisive call for field $i(".($i+1).") with text $text");
				parselogline(\%{ $$cfghashref{$i + 1} }, $tmp[$i], $linehashref);
			}
		}
	}
	logmsg (9, 4, "line results now ...", $linehashref);
}

sub processlogfile {
	my $cfghashref = shift;
	my $reshashref = shift;
	my $logfileref = shift;

	my $format = $$cfghashref{FORMAT}{default}; # TODO - make dynamic
	my %lastline;
	
	logmsg(5, 1, " and I was called by ... ".&whowasi);
	logmsg(5, 1, "Processing logfiles: ", $logfileref);
	foreach my $logfile (@$logfileref) {
		logmsg(1, 0, "processing $logfile using format $format...");
		
		open (LOGFILE, "<$logfile") or die "Unable to open $logfile for reading...";
		while (<LOGFILE>) {
			my $facility = "";
			my %line;
			# Placing line and line componenents into a hash to be passed to actrule, components can then be refered
			# to in action lines, ie {svr} instead of trying to create regexs to collect individual bits
			$line{line} = $_;

    		logmsg(5, 1, "Processing next line");
    		logmsg(9, 2, "Delimiter: $$cfghashref{FORMAT}{ $format }{fields}{delimiter}");
    		logmsg(9, 2, "totalfields: $$cfghashref{FORMAT}{$format}{fields}{totalfields}");
			#logmsg(5, 1, "skipping as line doesn't match the match regex") and 

    		parselogline(\%{ $$cfghashref{FORMAT}{$format}{fields} }, $line{line}, \%line);
    	
			logmsg(9, 1, "Checking line: $line{line}");
			logmsg(9, 2, "Extracted Field contents ...\n", \@{$line{fields}});
		
			if ($line{line} =~ /$MATCH/) {
				my %rules = matchrules(\%{ $$cfghashref{RULE} }, \%line );
				logmsg(9, 2, keys (%rules)." matches so far");

			#TODO Handle "Message repeated" type scenarios when we don't know which field should contatin the msg
			#UP to here	
			# FORMAT stanza contains a substanza which describes repeat for the given format
			# format{repeat}{cmd} - normally regex, not sure what other solutions would apply
			# format{repeat}{regex} - array of regex's hashes
			# format{repeat}{field} - the name of the field to apply the cmd (normally regex) to
		
			#TODO describe matching of multiple fields ie in syslog we want to match regex and also ensure that HOST matches previous previousline
			# Detect and count repeats
	    		if (keys %rules >= 0) {
					logmsg (5, 2, "matched ".keys(%rules)." rules from line $line{line}");

		    	# loop through matching rules and collect data as defined in the ACTIONS section of %config
		    		my $actrule = 0;
            		my %tmprules = %rules;
		    		for my $rule (keys %tmprules) {
		    			logmsg (9, 3, "checking rule: $rule");
						my $execruleret = 0;
						if (exists($$cfghashref{RULE}{$rule}{actions} ) ) {
		    				$execruleret = execrule(\@{ $$cfghashref{RULE}{$rule}{actions} }, $reshashref, $rule, \%line);
						} else {
							logmsg (2, 3, "No actions defined for rule; $rule");
						}
		    			logmsg (9, 4, "execrule returning $execruleret");
			    		delete $rules{$rule} unless $execruleret;
			 		# TODO: update &actionrule();
		    		}
					logmsg (9, 3, "#rules in list .., ".keys(%rules) );
					logmsg (9, 3, "\%rules ..", \%rules);
		    		$$reshashref{nomatch}[$#{$$reshashref{nomatch}}+1] = $line{line} if keys(%rules) == 0;
		    		# lastline & repeat
	    		} # rules > 0
				if (exists( $lastline{ $line{ $$cfghashref{FORMAT}{$format}{LASTLINEINDEX} } } ) ) {
					delete ($lastline{ $line{ $$cfghashref{FORMAT}{$format}{LASTLINEINDEX} } });
				}
				$lastline{ $line{ $$cfghashref{FORMAT}{$format}{LASTLINEINDEX} } } = %line;

				if ( keys(%rules) == 0) {
					# Add new unmatched linescode				
				}
			} else {
				logmsg(5, 1, "Not processing rules as text didn't match match regexp: /$MATCH/");
			}
			logmsg(9 ,1, "Results hash ...", \%$reshashref );
			logmsg (5, 1, "finished processing line");
		}
		close LOGFILE;
		logmsg (1, 0, "Finished processing $logfile.");
	} # loop through logfiles
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
# Bug
# Chops field at /, this is normally correct, except when a string value has a / such as a file path
# Ignore any escaping of \, i.e \/

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

=depricate
sub parsecfgline {
=head6 parsecfgline($line)
Depricated, use getparameter()
takes line as arg, and returns array of cmd and value (arg)
#=cut
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
=cut

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
	my $cfgfileref = shift;

	foreach my $cfgfile (@$cfgfileref) {
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
				logmsg(9, 3, "stanzatype: $stanzatype rulename:$rulename");
				logmsg(9, 3, "There are #".($#{$$cfghashref{$stanzatype}{$rulename}{actions}}+1)." elements so far in the action array.");
				setaction($$cfghashref{$stanzatype}{$rulename}{actions} , \@args);
			} elsif (/REPORT/) {
				setreport(\@{ $$cfghashref{$stanzatype}{$rulename}{reports} }, \@args);
			} else {
				# Assume to be a match
				$$cfghashref{$stanzatype}{$rulename}{fields}{$args[0]} = $args[1];		
			}# if cmd
		} # for cmd
	} # while
	close CFGFILE;
		logmsg (1, 0, "finished processing cfg: $cfgfile");
	}
	logmsg (5, 1, "Config Hash contents: ...", $cfghashref);
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
	logmsg (6, 5, "args passed: ", $argsref);
	logmsg (6, 5, "Actions so far .. ", $actionref);

	no strict;
	my $actionindex = $#{$actionref}+1;
	use strict;
	logmsg(5, 5, "There are # $actionindex so far, time to add another one.");
# ACTION formats:
#ACTION <field> </regex/> [<{matches}>] <command> [<command specific fields>] [LASTLINE]
#ACTION <field> </regex/> <{matches}> <sum|count> [<{sum field}>] [LASTLINE]
#ACTION <field> </regex/> <{matches}> append <rule> <{field transformation}> [LASTLINE]
# count - 4 or 5
# sum - 5 or 6
# append - 6 or 7

	$$actionref[$actionindex]{field} = $$argsref[1];
	$$actionref[$actionindex]{regex} = $$argsref[2];
	if ($$argsref[3] =~ /ignore/i) {
		logmsg(5, 6, "cmd is ignore");
		$$actionref[$actionindex]{cmd} = $$argsref[3];
	} else {
		logmsg(5, 6, "setting matches to $$argsref[3] & cmd to $$argsref[4]");
		$$actionref[$actionindex]{matches} = $$argsref[3];
		$$actionref[$actionindex]{cmd} = $$argsref[4];	
	if ($$argsref[4]) {
		logmsg (5, 6, "cmd is set in action cmd ... ");
		for ($$argsref[4]) {
			if (/^sum$/i) {
				$$actionref[$actionindex]{sourcefield} = $$argsref[5];
			} elsif (/^append$/i) {
				$$actionref[$actionindex]{appendtorule} = $$argsref[5];
				$$actionref[$actionindex]{fieldmap} = $$argsref[6];
			} elsif (/count/i) {
			} else {
				warning ("WARNING", "unrecognised command ($$argsref[4]) in ACTION command");
				logmsg (1, 6, "unrecognised command in cfg line @$argsref");
			}
		}
	} else {
		$$actionref[$actionindex]{cmd} = "count";
		logmsg (5, 6, "cmd isn't set in action cmd, defaulting to \"count\"");
	}
	}
	my @tmp = grep /^LASTLINE$/i, @$argsref;
	if ($#tmp >= 0) {
		$$actionref[$actionindex]{lastline} = 1; 
	}
	
	logmsg(5, 5, "action[$actionindex] for rule is now .. ", \%{ $$actionref[$actionindex] } );
	#$$actionref[$actionindex]{cmd} = $$argsref[4];
}

sub setreport {
=head6 fieldbasics ($cfghasref, @args)
where cfghashref should be a reference to the fields entry for the rule
REPORT "Sudo Usage" "{2} ran {4} as {3} on {1}: {x} times"
=cut

	my $reportref = shift;
	my $argsref = shift;

	logmsg (5, 4, " and I was called by ... ".&whowasi);
	logmsg (6, 5, "args: ", $argsref);
	logmsg (9, 5, "args: $$argsref[2]");
	no strict;	
	
	my $reportindex = $#{ $reportref } + 1;
	use strict;
	logmsg(9, 3, "reportindex: $reportindex");
	
	$$reportref[$reportindex]{title} = $$argsref[1];
	$$reportref[$reportindex]{line} = $$argsref[2];

	if ($$argsref[3] and $$argsref[3] =~ /^\/|\d+/) {
		logmsg(9,3, "report field regex: $$argsref[3]");
		($$reportref[$reportindex]{field}, $$reportref[$reportindex]{regex} ) = split (/=/, $$argsref[3], 2);
		#$$reportref[$reportindex]{regex} = $$argsref[3];
	}

	if ($$argsref[3] and $$argsref[3] !~ /^\/|\d+/) {
		$$reportref[$reportindex]{cmd} = $$argsref[3];
	} elsif ($$argsref[4] and $$argsref[4] !~ /^\/|\d+/) {
		$$reportref[$reportindex]{cmd} = $$argsref[4];	
	} else {
		$$reportref[$reportindex]{cmd} = "count";
	}
	
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
	logmsg (6, 5, "args: ", $argsref);
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
	logmsg (6, 5, "args: ", $argsref);
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

sub report {
	my $cfghashref = shift;
	my $reshashref = shift;
	#my $rpthashref = shift;

	logmsg(1, 0, "Runing report");
	logmsg (5, 0, " and I was called by ... ".&whowasi);

	logmsg(5, 1, "Dump of results hash ...", $reshashref);

	print "\n\nNo match for lines:\n";
	if (exists ($$reshashref{nomatch}) ) {
		foreach my $line (@{@$reshashref{nomatch}}) {
			print "\t$line";
		}
	}
	if ($COLOR) {
		print RED "\n\nSummaries:\n", RESET;
	} else {
		print "\n\nSummaries:\n";
	}
	for my $rule (sort keys %{ $$cfghashref{RULE} })  {
		next if $rule =~ /nomatch/;
		
		if (exists ($$cfghashref{RULE}{$rule}{reports} ) ) {
			for my $rptid (0 .. $#{ $$cfghashref{RULE}{$rule}{reports} } ) {
				logmsg (4, 1, "Processing report# $rptid for rule: $rule ...");
				my %ruleresults = summariseresults(\%{ $$cfghashref{RULE}{$rule} }, \%{ $$reshashref{$rule} });
				logmsg (5, 2, "\%ruleresults rule ($rule) report ID ($rptid) ... ", \%ruleresults);
				if (exists ($$cfghashref{RULE}{$rule}{reports}[$rptid]{title} ) ) {
					if ($COLOR) {
						print BLUE "$$cfghashref{RULE}{$rule}{reports}[$rptid]{title}\n", RESET;
					} else {
						print "$$cfghashref{RULE}{$rule}{reports}[$rptid]{title}\n";
					}
				} else {
					logmsg (4, 2, "Report has no title for rule: $rule\[$rptid\]");
				}
				
				for my $key (keys %{$ruleresults{$rptid} }) {
					logmsg (5, 3, "key:$key");
					if (exists ($$cfghashref{RULE}{$rule}{reports}[$rptid]{line})) {
						if ($COLOR) {
							print GREEN rptline(\% {$$cfghashref{RULE}{$rule}{reports}[$rptid] }, \%{$ruleresults{$rptid} }, $rule, $rptid, $key), RESET;
						} else {
							print rptline(\% {$$cfghashref{RULE}{$rule}{reports}[$rptid] }, \%{$ruleresults{$rptid} }, $rule, $rptid, $key);
						}
					} else {
						if ($COLOR) {
							print GREEN "\t$$reshashref{$rule}{$key}: $key\n", RESET;
						} else {
							print "\t$$reshashref{$rule}{$key}: $key\n";
						}
					}
				}
				print "\n";	
			} # for rptid
		} # if reports in %cfghash{RULE}{$rule}
	} # for rule in %reshashref
} #sub

sub summariseresults {
	my $cfghashref = shift; # passed $cfghash{RULE}{$rule}
	my $reshashref = shift; # passed $reshashref{$rule}
	#my $rule = shift;
	# loop through reshash for a given rule and combine the results of all the actions
	# returns a summarised hash
	
	my %results;
    logmsg (9, 5, "cfghashref ...", $cfghashref);
    logmsg (9, 5, "reshashref ...", $reshashref);
	
	for my $actionid (keys( %$reshashref ) ) {
    		logmsg (5, 5, "Processing actionid: $actionid ...");
		for my $key (keys %{ $$reshashref{$actionid} } ) {
			logmsg (5, 6, "Processing key: $key for actionid: $actionid");
			(my @values) = split (/:/, $key);
    		        logmsg (9, 7, "values from key($key) ... @values");

			for my $rptid (0 .. $#{ $$cfghashref{reports} }) {
				logmsg (5, 7, "Processing report ID:  $rptid with key: $key for actionid: $actionid");
				if (exists($$cfghashref{reports}[$rptid]{field})) {
					logmsg (9, 8, "Checking to see if field($$cfghashref{reports}[$rptid]{field}) in the results matches $$cfghashref{reports}[$rptid]{regex}");
					if ($values[$$cfghashref{reports}[$rptid]{field} - 1] =~ /$$cfghashref{reports}[$rptid]{regex}/) {
						logmsg(9, 9, $values[$$cfghashref{reports}[$rptid]{field} - 1]." is a match.");
					} else {
						logmsg(9, 9, $values[$$cfghashref{reports}[$rptid]{field} - 1]." isn't a match.");
						next;
					}
				}
				(my @targetfieldids) = $$cfghashref{reports}[$rptid]{line} =~ /(\d+?)/g;
				logmsg (9, 7, "targetfields (from $$cfghashref{reports}[$rptid]{line})... ", \@targetfieldids);

				# Compare max fieldid to number of entries in $key, skip if maxid > $key
				my $targetmaxfield = array_max(\@targetfieldids);
				if ($targetmaxfield > ($#values + 1) ) {
					logmsg (2, 5, "There is a field id ($targetmaxfield) in the target key greater than the number of fields ($#values) in the key, skipping");
					next;
				}
				
				my $targetkeymatch;# my $targetid;
				# create key using only fieldids required for rptline
				# field id's are relative to the fields collected by the action cmds
				for my $resfieldid (0 .. $#values) {# loop through the fields in the key from reshash (generated by action)
					my $fieldid = $resfieldid+1;

					logmsg (9, 8, "Checking for $fieldid in \@targetfieldids(@targetfieldids), \@values[$resfieldid] = $values[$resfieldid]");
					if (grep(/^$fieldid$/, @targetfieldids ) ) {
						$targetkeymatch .= ":$values[$resfieldid]";
						logmsg(9, 9, "fieldid: $fieldid occured in @targetfieldids, adding $values[$resfieldid] to \$targetkeymatch");
					} elsif ($fieldid == $$cfghashref{reports}[$rptid]{field} ) {
						$targetkeymatch .= ":$values[$resfieldid]";
						logmsg(9, 9, "fieldid: $fieldid is used report matching, so adding $values[$resfieldid] to \$targetkeymatch");
					} else {
						$targetkeymatch .= ":.*?";
						logmsg(9, 9, "fieldid: $fieldid wasn't listed in @targetfieldids, adding wildcard to \$targetkeymatch");
					}
					logmsg (9, 8, "targetkeymatch is now: $targetkeymatch");
				}
				$targetkeymatch =~ s/^://;

				$targetkeymatch =~ s/\(/\\\(/g;
				$targetkeymatch =~ s/\)/\\\)/g;
			
				logmsg (9, 7, "targetkey is $targetkeymatch");
				if ($key =~ /$targetkeymatch/) {
					$targetkeymatch =~ s/\\\(/\(/g;
					$targetkeymatch =~ s/\\\)/\)/g;
					logmsg (9, 8, "$key does matched $targetkeymatch, so I'm doing the necssary calcs ...");
					$results{$rptid}{$targetkeymatch}{count} += $$reshashref{$actionid}{$key}{count};
					logmsg (9, 9, "Incremented count for report\[$rptid\]\[$targetkeymatch\] by $$reshashref{$actionid}{$key}{count} so it's now $$reshashref{$actionid}{$key}{count}");
					$results{$rptid}{$targetkeymatch}{total} += $$reshashref{$actionid}{$key}{total};
					logmsg (9, 9, "Added $$reshashref{$actionid}{$key}{total} to total for report\[$rptid\]\[$targetkeymatch\], so it's now ... $results{$rptid}{$targetkeymatch}{count}");
					$results{$rptid}{$targetkeymatch}{avg} = $$reshashref{$actionid}{$key}{total} / $$reshashref{$actionid}{$key}{count};
					logmsg (9, 9, "Avg for report\[$rptid\]\[$targetkeymatch\] is now $results{$rptid}{$targetkeymatch}{avg}");
				} else {
					logmsg (9, 8, "$key does not match $targetkeymatch<eol>");
					logmsg (9, 8, "      key $key<eol>");
					logmsg (9, 8, "targetkey $targetkeymatch<eol>");
				}
			} # for $rptid in reports
		} # for rule/actionid/key 
	}  # for rule/actionid
	
	logmsg (9, 5, "Returning ... results", \%results);

	return %results;
}

sub rptline {
	my $cfghashref = shift; # %cfghash{RULE}{$rule}{reports}{$rptid}
	my $reshashref = shift; # reshash{$rule}
	#my $rpthashref = shift;
	my $rule = shift;
	my $rptid = shift;
	my $key = shift;

	logmsg (5, 2, " and I was called by ... ".&whowasi);
#    logmsg (3, 2, "Starting with rule:$rule & report id:$rptid");
    logmsg (9, 3, "key: $key");
 
	# generate rpt line based on config spec for line and results.
	# Sample entry: {x}: logouts from {2} by {1}
	
	logmsg (7, 3, "cfghash ... ", $cfghashref);
	logmsg (7, 3, "reshash ... ", $reshashref);
	my $line = "\t".$$cfghashref{line};
    logmsg (7, 3, "report line: $line");
  
  	for ($$cfghashref{cmd})  {
    	if (/count/i) {
     		$line =~ s/\{x\}/$$reshashref{$key}{count}/;
     		logmsg(9, 3, "subsituting {x} with $$reshashref{$key}{count} (count)");
    	} elsif (/SUM/i) {
     		$line =~ s/\{x\}/$$reshashref{$key}{total}/;
     		logmsg(9, 3, "subsituting {x} with $$reshashref{$key}{total} (total)");
     	} elsif (/AVG/i) {
        	my $avg = $$reshashref{$key}{total} / $$reshashref{$key}{count};
        	$avg = sprintf ("%.3f", $avg);
	    	$line =~ s/\{x\}/$avg/;
	    	logmsg(9, 3, "subsituting {x} with $avg (avg)");
     	} else {
     		logmsg (1, 0, "WARNING: Unrecognized cmd ($$cfghashref{cmd}) for report #$rptid in rule ($rule)");
   		}
	}

	my @fields = split /:/, $key;
    logmsg (9, 3, "#fields ".($#fields+1)." in @fields");
	for my $i (0..$#fields) {
		my $field = $i+1;
        logmsg (9, 4, "Settting \$fields[$field] ($fields[$field]) = \$fields[$i] ($fields[$i])");
		if ($line =~ /\{$field\}/) {
			$line =~ s/\{$field\}/$fields[$i]/;
		}
	}

	$line.="\n";

	#if (exists($$cfghashref{field})) {
		#logmsg (9, 4, "Checking to see if field($$cfghashref{field}) in the results matches $$cfghashref{regex}");
		#if ($fields[$$cfghashref{field} - 1] =~ /$$cfghashref{regex}/) {
			#logmsg(9, 5, $fields[$$cfghashref{field} - 1]." is a match.");
			#$line = "";
		#}
	#}

	logmsg (7, 3, "report line is now:$line");
	return $line;
}

sub getmatchlist {
	# given a match field, return 2 lists
	# list 1: all fields in that list
	# list 2: only numeric fields in the list
	
	my $matchlist = shift;
	my $numericonly = shift;
	
	my @matrix = split (/,/, $matchlist);

	logmsg (9, 5, "Matchlist ... $matchlist");
	logmsg (9, 5, "Matchlist has morphed in \@matrix with elements ... ", \@matrix);
    if ($matchlist !~ /,/) {
    	push @matrix, $matchlist;
		logmsg (9, 6, "\$matchlist didn't have a \",\", so we shoved it onto \@matrix. Which is now ... ", \@matrix);
    }
    my @tmpmatrix = ();
    for my $i (0 .. $#matrix) {
		logmsg (9, 7, "\$i: $i");
    	$matrix[$i] =~ s/\s+//g;
    	if ($matrix[$i] =~ /\d+/) {
    		push @tmpmatrix, $matrix[$i];
			logmsg (9, 8, "element $i ($matrix[$i]) was an integer so we pushed it onto the matrix");
    	} else {
			logmsg (9, 8, "element $i ($matrix[$i]) wasn't an integer so we ignored it");
		}
    }
    
    if ($numericonly) {
		logmsg (9, 5, "Returning numeric only results ... ", \@tmpmatrix);
    	return @tmpmatrix;
    } else {
		logmsg (9, 5, "Returning full results ... ", \@matrix);
    	return @matrix;
    }
}
#TODO rename actionrule to execaction, execaction should be called from execrule
#TODO extract handling of individual actions
sub execaction {
	my $cfghashref = shift; # ref to $cfghash{RULES}{$rule}{actions}[$actionid]
	my $reshashref = shift;
	my $rule = shift;
	my $actionid = shift;
	my $line = shift; # hash passed by ref, DO NOT mod
	
	logmsg (7, 4, "Processing line with rule ${rule}'s action# $actionid using matches $$cfghashref{matches}");
	my @matrix = getmatchlist($$cfghashref{matches}, 0);
	my @tmpmatrix = getmatchlist($$cfghashref{matches}, 1); 

	if ($#tmpmatrix == -1 ) {
		logmsg (7, 5, "hmm, no entries in tmpmatrix and there was ".($#matrix+1)." entries for \@matrix.");
	} else {
    	logmsg (7, 5, ($#tmpmatrix + 1)." entries for matching, using list @tmpmatrix");
	}
	logmsg (9, 6, "rule spec: ", $cfghashref);
    my $retval = 0;
   	my $matchid;
   	my @resmatrix = ();
    no strict;
    if ($$cfghashref{regex} =~ /^\!/) {
    	my $regex = $$cfghashref{regex};
    	$regex =~ s/^!//;
    	logmsg(8, 5, "negative regex - !$regex");
    	if ($$line{ $$cfghashref{field} } !~ /$regex/ ) {
    		logmsg(8, 6, "line matched regex");
			for my $val (@tmpmatrix) {
				push @resmatrix, ${$val};
				logmsg (9,6, "Adding ${$val} (from match: $val) to matrix");
			}
			$matchid = populatematrix(\@resmatrix, $$cfghashref{matches}, $line);
			$retval = 1;
    	}
    } else {
    	logmsg(8, 5, "Using regex - $$cfghashref{regex} on field content $$line{ $$cfghashref{field} }");
    	if ($$line{ $$cfghashref{field} } =~ /$$cfghashref{regex}/ ) {
    		logmsg(8, 6, "line matched regex");
			for my $val (@tmpmatrix) {
				push @resmatrix, ${$val};
				logmsg (9,6, "Adding ${$val} (from match: $val) to matrix");
			}
			$matchid = populatematrix(\@resmatrix, $$cfghashref{matches}, $line);
			$retval = 1;
    	}
    	logmsg(6, 5, "matrix for rule ... @matrix & matchid $matchid");
    }
	use strict;
	if ($retval) {
		if (exists($$cfghashref{cmd} ) ) {
    	for ($$cfghashref{cmd}) {
    		logmsg (7, 6, "Processing $$cfghashref{cmd} for $rule [$actionid]");
    		if (/count/i) {
    			$$reshashref{$rule}{$actionid}{$matchid}{count}++;		
    		} elsif (/sum/i) {
    			$$reshashref{$rule}{$actionid}{$matchid}{total} += $resmatrix[ $$cfghashref{sourcefield} ];
    			$$reshashref{$rule}{$actionid}{$matchid}{count}++;
    		} elsif (/append/i) {
    			
    		} elsif (/ignore/i) {
    		} else {
    			warning ("w", "unrecognised cmd ($$cfghashref{cmd}) in action ($actionid) for rule: $rule");
    			logmsg(1, 5, "unrecognised cmd ($$cfghashref{cmd}) in action ($actionid) for rule: $rule");
    		}
				}
    	} else {
			logmsg(1, 5, "hmmm, no cmd set for rule ($rule)'s actionid: $actionid. The cfghashref data is .. ", $cfghashref);
		}
    }	
   	logmsg (7, 5, "returning: $retval");
	return $retval;
}

sub execrule {
	# Collect data for rule $rule as defined in the ACTIONS section of %config
	# returns 0 if unable to apply rule, else returns 1 (success)
	# use ... actionrule($cfghashref{RULE}, $reshashref, $rule, \%line);	 
	my $cfghashref = shift; # ref to $cfghash{RULES}{$rule}{actions}
	my $reshashref = shift;
	my $rule = shift;
	my $line = shift; # hash passed by ref, DO NOT mod
#	my $retvalue;
	my $retval = 0;
	#my $resultsrule;

	logmsg (5, 2, " and I was called by ... ".&whowasi);
    logmsg (6, 3, "rule: $rule called for $$line{line}");
    
    logmsg (9, 3, (@$cfghashref)." actions for rule: $rule");
	logmsg (9, 3, "cfghashref .. ", $cfghashref);
    for my $actionid ( 0 .. (@$cfghashref - 1) ) {
    	logmsg (6, 4, "Processing action[$actionid]");
    	# actionid needs to recorded in resultsref as well as ruleid

		if (exists($$cfghashref[$actionid])) {
    	$retval += execaction(\%{ $$cfghashref[$actionid] }, $reshashref, $rule, $actionid, $line ); 	
	} else 	 {
		logmsg (6, 3, "\$\$cfghashref[$actionid] doesn't exist, but according to the loop counter it should !! ");
	}

    }
    logmsg (7, 2, "After checking all actions for this rule; \%reshash ...", $reshashref);
    
    return $retval;
}

sub populatematrix {
	#my $cfghashref = shift; # ref to $cfghash{RULES}{$rule}{actions}{$actionid}
	#my $reshashref = shift;
	my $resmatrixref = shift;
	my $matchlist = shift;
	my $lineref = shift; # hash passed by ref, DO NOT mod
	my $matchid;
	
	logmsg (9, 5, "\@resmatrix ... ", $resmatrixref) ;
	
	my @matrix = getmatchlist($matchlist, 0);
	my @tmpmatrix = getmatchlist($matchlist, 1); 
	logmsg (9, 6, "\@matrix ..", \@matrix);
	logmsg (9, 6, "\@tmpmatrix ..", \@tmpmatrix);
	
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

sub defaultregex {
    # expects a reference to the rule and param
    my $paramref = shift;
    logmsg(5, 4, " and I was called by ... ".&whowasi);
    #   profile( whoami(), whowasi() );
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
	logmsg (9, 4, "cfghashref:", $cfghashref);
    for my $rule (keys %{ $cfghashref } ) {
		logmsg (9, 4, "Checking to see if $rule applies ...");
		if (matchfields(\%{ $$cfghashref{$rule}{fields} } , $linehashref)) {
    		$rules{$rule} = $rule ;
			logmsg (9, 5, "it matches");
		} else {
			logmsg (9, 5, "it doesn't match");
		}
    }
    
	return %rules;
}

sub matchfields {
	my $cfghashref = shift; # expects to be passed $$cfghashref{RULES}{$rule}{fields}
	my $linehashref = shift;
	my $ret = 1;	# 1 = match, 0 = fail
	# Assume fields match.
	# Only fail if a field doesn't match.
	# Passed a cfghashref to a rule

	logmsg (9, 5, "cfghashref:", $cfghashref);
	if (exists ( $$cfghashref{fields} ) ) {
		logmsg (9, 5, "cfghashref{fields}:", \%{ $$cfghashref{fields} });
	}
	logmsg (9, 5, "linehashref:", $linehashref);

	foreach my $field (keys (%{ $cfghashref } ) ) {
		logmsg(9, 6, "checking field: $field with value: $$cfghashref{$field}");
		logmsg (9, 7, "Does field ($field) with value: $$linehashref{ $field } match the following regex ...");
		if ($$cfghashref{$field} =~ /^!/) {
			my $exp = $$cfghashref{$field};
			$exp =~ s/^\!//;
			$ret = 0 unless ($$linehashref{ $field } !~ /$exp/);
			logmsg (9, 8, "neg regexp compar /$$linehashref{ $field }/ !~ /$exp/, ret=$ret");
		} else {
			$ret = 0 unless ($$linehashref{ $field } =~ /$$cfghashref{$field}/);
			logmsg (9, 8, "regexp compar /$$linehashref{$field}/ =~ /$$cfghashref{$field}/, ret=$ret");
		}
	}
	return $ret;
}
    
sub whoami  { (caller(1) )[3] }
sub whowasi { (caller(2) )[3] }

sub logmsg {
    my $level = shift;
    my $indent = shift;
    my $msg = shift;
	my $dumpvar = shift;
	my $time = time() - $STARTTIME;

    if ($DEBUG >= $level) {
		# TODO replace this with a regex so \n can also be matched and multi line (ie Dumper) can be correctly formatted
        for my $i (0..$indent) {
            print STDERR "  ";
        }
	if ($COLOR) {
        	print STDERR GREEN whowasi."(): d=${time}s:", RESET;
	} else {
        	print STDERR whowasi."(): d=${time}s:";
	}
		print STDERR " $msg";
		if ($dumpvar) {
			if ($COLOR) {
				print STDERR BLUE Dumper($dumpvar), RESET;
			} else {
				print STDERR Dumper($dumpvar);
			}
		}
		print STDERR "\n";
    }
}

sub warning {
    my $level = shift;
    my $msg = shift;

    for ($level) {
    	if (/w|warning/i) {
    		if ($COLOR >= 1) {
				print RED, "WARNING: $msg\n", RESET;
			} else {
    			print "WARNING: $msg\n";
			}
    	} elsif (/e|error/i)  {
			if ($COLOR >= 1) {
    			print RED, "ERROR: $msg\n", RESET;
			} else {
    			print "ERROR: $msg\n";
			}
    	} elsif (/c|critical/i) {
			if ($COLOR >= 1) {
    			print RED, "CRITICAL error, aborted ... $msg\n", RESET;
			} else {
				print "CRITICAL error, aborted ... $msg\n";
			}
    		exit 1;
    	} else {
    		warning("warning", "No warning message level set");
    	}
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

sub array_max {
	my $arrayref = shift; # ref to array

	my $highestvalue = $$arrayref[0];
	for my $i (0 .. @$arrayref ) {
		$highestvalue = $$arrayref[$i] if $$arrayref[$i] > $highestvalue;
	}

	return $highestvalue;
}

