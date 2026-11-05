#!/usr/bin/env perl
#
# Validate the shared Agent Knowledge Validation contract.
#
# The canonical Agent Knowledge Validation implementation.
# It uses only core modules and Git. The command line, rule identifiers,
# output formats, and exit codes are intentionally compatible.
#
# See the LICENSE file at the top of the project tree for copyright
# and license details.

use 5.014;
use strict;
use warnings;

use Cwd            qw(abs_path getcwd realpath);
use Encode         qw(decode encode FB_CROAK FB_DEFAULT);
use File::Basename qw(basename dirname);
use File::Spec;
use IO::Select;
use IPC::Open3 qw(open3);
use JSON::PP   ();
use Symbol     qw(gensym);

my $CONTRACT_VERSION = '1.0.0';
my $SCHEMA_VERSION   = '1.0';
my $CONFIG_NAME      = '.agent-knowledge-validator.toml';

my %RULE_NAMES = (
    AK001 => 'Agent knowledge synchronization',
    AK002 => 'Agent and skill structure',
    AK003 => 'Internal references',
    AK004 => 'Knowledge update relevance',
    AK005 => 'Validator configuration and execution',
    AK006 => 'Duplicate or conflicting instructions',
);

my %INSTRUCTION_NAMES = map { $_ => 1 } (
    'AGENTS.md',    'AGENT.md',
    'SKILL.md',     'CLAUDE.md',
    'GEMINI.md',    'copilot-instructions.md',
    '.cursorrules', '.windsurfrules',
);

my @INSTRUCTION_SUFFIXES = ( '.agent.md', '.instructions.md', '.mdc' );

my @INFRASTRUCTURE_PATTERNS = (
    'scripts/validate-agent-knowledge.pl',
    '**/scripts/validate-agent-knowledge.pl',
    'tests/agent_knowledge_validator/**',
    '**/tests/agent_knowledge_validator/**',
    '.github/workflows/agent-knowledge-validation.yml',
    '**/agent-knowledge-validation.yml',
    '**/agent-knowledge-validation.yaml',
);

my @DEFAULT_EXCLUDED_PATHS = ();

#
# Git execution. No shell is involved; every argument is passed as a list.
#

sub capture_command {
    my (@command) = @_;
    my $stderr_handle = gensym;
    my ( $input, $output );
    my $pid = open3( $input, $output, $stderr_handle, @command );
    close $input;
    binmode $output;
    binmode $stderr_handle;

    my $stdout_fd = fileno($output);
    my $selector  = IO::Select->new( $output, $stderr_handle );
    my ( $stdout, $stderr ) = ( '', '' );
    while ( my @ready = $selector->can_read() ) {
        for my $handle (@ready) {
            my $chunk;
            my $count = sysread( $handle, $chunk, 8192 );
            if ( !defined $count ) {
                $selector->remove($handle);
                close $handle;
                next;
            }
            if ( $count == 0 ) {
                $selector->remove($handle);
                close $handle;
                next;
            }
            if ( fileno($handle) == $stdout_fd ) {
                $stdout .= $chunk;
            }
            else {
                $stderr .= $chunk;
            }
        }
    }
    waitpid( $pid, 0 );
    my $status = $? >> 8;
    return ( $stdout, $stderr, $status );
}

sub trim_text {
    my ($value) = @_;
    return '' unless defined $value;
    $value =~ s/^\s+//;
    $value =~ s/\s+$//;
    return $value;
}

sub split_text_lines {
    my ($value) = @_;
    return () unless defined $value && $value ne '';
    return split /\r\n|[\n\r\v\f\x1c\x1d\x1e\x85\x{2028}\x{2029}]/, $value;
}

sub run_git_optional {
    my ( $root, @arguments ) = @_;
    my ( $stdout, $stderr, $status ) =
      capture_command( 'git', '-C', $root, @arguments );
    return ( decode( 'UTF-8', $stdout, FB_DEFAULT ),
        decode( 'UTF-8', $stderr, FB_DEFAULT ), $status );
}

sub run_git {
    my ( $root, @arguments ) = @_;
    my ( $stdout, $stderr, $status ) = run_git_optional( $root, @arguments );
    if ($status) {
        my $detail = trim_text($stderr);
        $detail = 'git ' . join( ' ', @arguments ) . ' failed'
          if $detail eq '';
        die $detail . "\n";
    }
    return $stdout;
}

sub find_repository_root {
    my ($cwd)    = @_;
    my $output   = run_git( $cwd, 'rev-parse', '--show-toplevel' );
    my $root     = trim_text($output);
    my $resolved = realpath($root);
    $resolved = abs_path($root)            unless defined $resolved;
    $resolved = File::Spec->rel2abs($root) unless defined $resolved;
    return $resolved;
}

sub resolve_commit {
    my ( $root, $revision ) = @_;
    my ( $stdout, $stderr, $status ) =
      run_git_optional( $root, 'rev-parse', '--verify',
        $revision . '^{commit}' );
    if ($status) {
        die "revision does not resolve to a commit: $revision\n";
    }
    return trim_text($stdout);
}

#
# A small, strict TOML reader for the configuration subset documented by the
# contract. It intentionally supports only what the validator configuration
# can use:
#
#   * [validator] and nested tables such as [validator.required_headings]
#   * bare, quoted, and dotted keys
#   * basic and literal single-line strings with TOML escapes
#   * arrays, including multiline arrays with trailing commas
#   * booleans, decimal integers, and inline tables
#   * comments and CRLF input
#
# Unsupported constructs (arrays of tables, floats, dates/times, multiline
# strings, hexadecimal/octal/binary integers, and bare values outside this
# subset) are rejected with exit code 2. The parser is stricter than a full
# TOML implementation; it must not be reused as a general TOML library.
# Table key iteration is not used as contract output, so mapping order is
# not preserved where the validator sorts patterns for deterministic output.
#

{

    package AKV::Int;
    sub value { return ${ $_[0] }; }

    package AKV::Bool;
    sub value { return ${ $_[0] }; }

    package main;
}

sub toml_integer {
    my ($value) = @_;
    return bless \$value, 'AKV::Int';
}

sub toml_boolean {
    my ($value) = @_;
    my $stored = $value ? 1 : 0;
    return bless \$stored, 'AKV::Bool';
}

sub toml_die {
    my ( $line, $message ) = @_;
    die "line $line: $message\n";
}

sub strip_toml_comment {
    my ($line) = @_;
    my $result = '';
    my $quote  = '';
    my $escape = 0;
    for my $character ( split //, $line ) {
        if ( $quote eq '"' ) {
            if ($escape) {
                $escape = 0;
            }
            elsif ( $character eq '\\' ) {
                $escape = 1;
            }
            elsif ( $character eq '"' ) {
                $quote = '';
            }
            $result .= $character;
            next;
        }
        if ( $quote eq "'" ) {
            $quote = '' if $character eq "'";
            $result .= $character;
            next;
        }
        if ( $character eq '"' || $character eq "'" ) {
            $quote = $character;
            $result .= $character;
            next;
        }
        last if $character eq '#';
        $result .= $character;
    }
    return $result;
}

sub split_toml_key_path {
    my ( $raw, $line ) = @_;
    my @parts;
    my $current = '';
    my $quote   = '';
    my $escape  = 0;
    for my $character ( split //, $raw ) {
        if ( $quote eq '"' ) {
            if ($escape) {
                $current .= $character;
                $escape = 0;
                next;
            }
            if ( $character eq '\\' ) {
                $current .= $character;
                $escape = 1;
                next;
            }
            if ( $character eq '"' ) {
                $current .= $character;
                $quote = '';
                next;
            }
            $current .= $character;
            next;
        }
        if ( $quote eq "'" ) {
            $current .= $character;
            $quote = '' if $character eq "'";
            next;
        }
        if ( $character eq '"' || $character eq "'" ) {
            $quote = $character;
            $current .= $character;
            next;
        }
        if ( $character eq '.' ) {
            push @parts, $current;
            $current = '';
            next;
        }
        $current .= $character;
    }
    toml_die( $line, 'unterminated quoted key' ) if $quote ne '';
    push @parts, $current;

    my @keys;
    for my $part (@parts) {
        $part =~ s/^\s+//;
        $part =~ s/\s+$//;
        toml_die( $line, 'empty key component' ) if $part eq '';
        if ( $part =~ /^"/ ) {
            my ( $value, $rest ) = parse_toml_string( $part, $line );
            toml_die( $line, 'invalid quoted key' ) if trim_text($rest) ne '';
            push @keys, $value;
        }
        elsif ( $part =~ /^'/ ) {
            my ( $value, $rest ) = parse_toml_literal_string( $part, $line );
            toml_die( $line, 'invalid quoted key' ) if trim_text($rest) ne '';
            push @keys, $value;
        }
        else {
            toml_die( $line, "invalid bare key: $part" )
              unless $part =~ /^[A-Za-z0-9_-]+$/;
            push @keys, $part;
        }
    }
    return @keys;
}

sub split_toml_assignment {
    my ( $line_text, $line ) = @_;
    my $quote  = '';
    my $escape = 0;
    my $index  = 0;
    for my $character ( split //, $line_text ) {
        if ( $quote eq '"' ) {
            if ($escape) {
                $escape = 0;
            }
            elsif ( $character eq '\\' ) {
                $escape = 1;
            }
            elsif ( $character eq '"' ) {
                $quote = '';
            }
            $index++;
            next;
        }
        if ( $quote eq "'" ) {
            $quote = '' if $character eq "'";
            $index++;
            next;
        }
        if ( $character eq '"' || $character eq "'" ) {
            $quote = $character;
            $index++;
            next;
        }
        if ( $character eq '=' ) {
            my $key  = substr( $line_text, 0, $index );
            my $rest = substr( $line_text, $index + 1 );
            return ( $key, $rest );
        }
        $index++;
    }
    toml_die( $line, 'expected key = value' );
}

sub parse_toml_string {
    my ( $raw, $line ) = @_;
    toml_die( $line, 'unterminated string' )
      unless $raw =~ /^"/;
    my $result = '';
    my $length = length($raw);
    my $index  = 1;
    while ( $index < $length ) {
        my $character = substr( $raw, $index, 1 );
        $index++;
        if ( $character eq '"' ) {
            return ( $result, substr( $raw, $index ) );
        }
        if ( $character eq '\\' ) {
            toml_die( $line, 'unterminated string escape' )
              if $index >= $length;
            my $escape = substr( $raw, $index, 1 );
            $index++;
            if    ( $escape eq 'b' )  { $result .= "\b"; }
            elsif ( $escape eq 't' )  { $result .= "\t"; }
            elsif ( $escape eq 'n' )  { $result .= "\n"; }
            elsif ( $escape eq 'f' )  { $result .= "\f"; }
            elsif ( $escape eq 'r' )  { $result .= "\r"; }
            elsif ( $escape eq '"' )  { $result .= '"'; }
            elsif ( $escape eq '\\' ) { $result .= '\\'; }
            elsif ( $escape eq 'u' || $escape eq 'U' ) {
                my $digits = $escape eq 'u' ? 4 : 8;
                my $hex    = substr( $raw, $index, $digits );
                $index += $digits;
                toml_die( $line, 'invalid unicode escape' )
                  if length($hex) != $digits || $hex !~ /^[0-9A-Fa-f]+$/;
                my $codepoint = hex($hex);
                toml_die( $line, 'invalid unicode codepoint' )
                  if $codepoint > 0x10FFFF
                  || ( $codepoint >= 0xD800 && $codepoint <= 0xDFFF );
                $result .= chr($codepoint);
            }
            else {
                toml_die( $line, "invalid string escape: \\$escape" );
            }
            next;
        }
        $result .= $character;
    }
    toml_die( $line, 'unterminated string' );
}

sub parse_toml_literal_string {
    my ( $raw, $line ) = @_;
    toml_die( $line, 'unterminated literal string' )
      unless $raw =~ /^'/;
    my $end = index( $raw, "'", 1 );
    toml_die( $line, 'unterminated literal string' ) if $end < 0;
    return ( substr( $raw, 1, $end - 1 ), substr( $raw, $end + 1 ) );
}

sub split_toml_items {
    my ( $raw, $line ) = @_;
    my @items;
    my $current = '';
    my @braces;
    my $quote  = '';
    my $escape = 0;
    for my $character ( split //, $raw ) {
        if ( $quote eq '"' ) {
            if ($escape) {
                $current .= $character;
                $escape = 0;
                next;
            }
            if ( $character eq '\\' ) {
                $current .= $character;
                $escape = 1;
                next;
            }
            if ( $character eq '"' ) {
                $current .= $character;
                $quote = '';
                next;
            }
            $current .= $character;
            next;
        }
        if ( $quote eq "'" ) {
            $current .= $character;
            $quote = '' if $character eq "'";
            next;
        }
        if ( $character eq '"' || $character eq "'" ) {
            $quote = $character;
            $current .= $character;
            next;
        }
        if ( $character eq '[' ) {
            push @braces, ']';
            $current .= $character;
            next;
        }
        if ( $character eq '{' ) {
            push @braces, '}';
            $current .= $character;
            next;
        }
        if ( $character eq ']' || $character eq '}' ) {
            toml_die( $line, 'unbalanced closing bracket' ) unless @braces;
            my $expected = pop @braces;
            toml_die( $line, 'mismatched closing bracket' )
              if $character ne $expected;
            $current .= $character;
            next;
        }
        if ( $character eq ',' && !@braces ) {
            push @items, $current;
            $current = '';
            next;
        }
        $current .= $character;
    }
    toml_die( $line, 'unterminated quoted value' ) if $quote ne '';
    toml_die( $line, 'unbalanced brackets' )       if @braces;
    push @items, $current;
    return @items;
}

sub parse_toml_value {
    my ( $raw, $line ) = @_;
    my $value = trim_text($raw);
    toml_die( $line, 'missing value' ) if $value eq '';
    if ( $value =~ /^"/ ) {
        my ( $parsed, $rest ) = parse_toml_string( $value, $line );
        toml_die( $line, 'unexpected text after string' )
          if trim_text($rest) ne '';
        return $parsed;
    }
    if ( $value =~ /^'/ ) {
        my ( $parsed, $rest ) = parse_toml_literal_string( $value, $line );
        toml_die( $line, 'unexpected text after string' )
          if trim_text($rest) ne '';
        return $parsed;
    }
    if ( $value =~ /^\[/ ) {
        toml_die( $line, 'unterminated array' ) unless $value =~ /\]$/;
        my $inner = substr( $value, 1, length($value) - 2 );
        my @items = split_toml_items( $inner, $line );
        my @parsed;
        for my $index ( 0 .. $#items ) {
            my $item = trim_text( $items[$index] );
            if ( $item eq '' ) {
                next if $index == $#items;
                toml_die( $line, 'missing array value' );
            }
            push @parsed, parse_toml_value( $item, $line );
        }
        return \@parsed;
    }
    if ( $value =~ /^\{/ ) {
        toml_die( $line, 'unterminated inline table' )
          unless $value =~ /\}$/;
        my $inner = substr( $value, 1, length($value) - 2 );
        my @items = split_toml_items( $inner, $line );
        my $table = {};
        for my $index ( 0 .. $#items ) {
            my $item = trim_text( $items[$index] );
            if ( $item eq '' ) {
                next if $index == $#items && !%{$table};
                toml_die( $line, 'missing inline table entry' );
            }
            my ( $key_text, $rest ) = split_toml_assignment( $item, $line );
            my @keys       = split_toml_key_path( $key_text, $line );
            my $item_value = parse_toml_value( $rest, $line );
            set_toml_value( $table, \@keys, $item_value, $line );
        }
        return $table;
    }
    if    ( $value eq 'true' )  { return toml_boolean(1); }
    elsif ( $value eq 'false' ) { return toml_boolean(0); }
    elsif ( $value =~ /^[+-]?(?:0|[1-9](?:_?[0-9])*)$/ ) {
        $value =~ s/_//g;
        return toml_integer( 0 + $value );
    }
    toml_die( $line, "unsupported TOML value: $value" );
}

sub value_bracket_delta {
    my ($raw)  = @_;
    my $delta  = 0;
    my $quote  = '';
    my $escape = 0;
    for my $character ( split //, $raw ) {
        if ( $quote eq '"' ) {
            if ($escape) {
                $escape = 0;
            }
            elsif ( $character eq '\\' ) {
                $escape = 1;
            }
            elsif ( $character eq '"' ) {
                $quote = '';
            }
            next;
        }
        if ( $quote eq "'" ) {
            $quote = '' if $character eq "'";
            next;
        }
        if ( $character eq '"' || $character eq "'" ) {
            $quote = $character;
            next;
        }
        $delta++ if $character eq '[' || $character eq '{';
        $delta-- if $character eq ']' || $character eq '}';
    }
    return ( $delta, $quote, $escape );
}

sub set_toml_value {
    my ( $table, $keys, $value, $line ) = @_;
    my $cursor = $table;
    for my $index ( 0 .. $#$keys - 1 ) {
        my $key = $keys->[$index];
        if ( !exists $cursor->{$key} ) {
            $cursor->{$key} = {};
        }
        elsif ( ref( $cursor->{$key} ) ne 'HASH' ) {
            toml_die( $line, "key is not a table: $key" );
        }
        $cursor = $cursor->{$key};
    }
    my $last = $keys->[-1];
    toml_die( $line, "duplicate key: $last" ) if exists $cursor->{$last};
    $cursor->{$last} = $value;
    return;
}

sub navigate_toml_table {
    my ( $root, $keys, $line, $explicit ) = @_;
    my $cursor = $root;
    for my $key ( @{$keys} ) {
        if ( !exists $cursor->{$key} ) {
            $cursor->{$key} = {};
        }
        elsif ( ref( $cursor->{$key} ) ne 'HASH' ) {
            toml_die( $line, "key is not a table: $key" );
        }
        $cursor = $cursor->{$key};
    }
    my $path = join( "\0", @{$keys} );
    toml_die( $line, 'duplicate table declaration' )
      if $explicit->{$path};
    $explicit->{$path} = 1;
    return $cursor;
}

sub parse_toml {
    my ($text) = @_;
    $text = '' unless defined $text;
    $text =~ s/^\x{FEFF}//;
    my @lines = split /\n/, $text, -1;
    my $root  = {};
    my %explicit_tables;
    my $current     = $root;
    my $line_number = 0;

    while ( $line_number < @lines ) {
        my $line = $lines[$line_number];
        $line_number++;
        $line =~ s/\r$//;
        my $clean = strip_toml_comment($line);
        next if trim_text($clean) eq '';

        if ( $clean =~ /^\s*\[\[/ ) {
            toml_die( $line_number, 'arrays of tables are not supported' );
        }
        if ( $clean =~ /^\s*\[(.*)\]\s*$/ ) {
            my $header = $1;
            my @keys   = split_toml_key_path( $header, $line_number );
            toml_die( $line_number, 'empty table name' ) unless @keys;
            $current =
              navigate_toml_table( $root, \@keys, $line_number,
                \%explicit_tables );
            next;
        }

        my ( $key_text, $rest ) = split_toml_assignment( $clean, $line_number );
        my @keys = split_toml_key_path( $key_text, $line_number );
        toml_die( $line_number, 'empty key' ) unless @keys;

        my $value_text = $rest;
        my ( $delta, $quote, $escape ) = value_bracket_delta($value_text);
        toml_die( $line_number, 'unterminated quoted value' )
          if $quote ne '';
        while ( $delta > 0 ) {
            toml_die( $line_number, 'unterminated array or inline table' )
              if $line_number >= @lines;
            my $continuation = $lines[$line_number];
            $line_number++;
            $continuation =~ s/\r$//;
            $continuation = strip_toml_comment($continuation);
            $value_text .= "\n" . $continuation;
            ( $delta, $quote, $escape ) = value_bracket_delta($value_text);
            toml_die( $line_number, 'unterminated quoted value' )
              if $quote ne '';
        }
        toml_die( $line_number, 'unbalanced brackets' ) if $delta < 0;

        my $value = parse_toml_value( $value_text, $line_number );
        set_toml_value( $current, \@keys, $value, $line_number );
    }
    return $root;
}

#
# Path and glob helpers. fnmatchcase is implemented directly so that '*'
# and '?' can cross '/' exactly as they do in the contract tests.
#

my %GLOB_REGEX_CACHE;

sub fnmatch_pattern {
    my ($pattern) = @_;
    return $GLOB_REGEX_CACHE{$pattern} if exists $GLOB_REGEX_CACHE{$pattern};

    my $regex  = '';
    my $length = length($pattern);
    my $index  = 0;
    while ( $index < $length ) {
        my $character = substr( $pattern, $index, 1 );
        $index++;
        if ( $character eq '*' ) {
            $regex .= '.*';
            next;
        }
        if ( $character eq '?' ) {
            $regex .= '.';
            next;
        }
        if ( $character eq '[' ) {
            my $cursor = $index;
            $cursor++
              if $cursor < $length && substr( $pattern, $cursor, 1 ) eq '!';
            $cursor++
              if $cursor < $length && substr( $pattern, $cursor, 1 ) eq ']';
            while ( $cursor < $length
                && substr( $pattern, $cursor, 1 ) ne ']' )
            {
                $cursor++;
            }
            if ( $cursor >= $length ) {
                $regex .= '\[';
                next;
            }
            my $stuff = substr( $pattern, $index, $cursor - $index );
            $index = $cursor + 1;
            $stuff =~ s/\\/\\\\/g;
            if ( $stuff =~ s/^!// ) {
                $regex .= '[^' . $stuff . ']';
            }
            else {
                $regex .= '[' . $stuff . ']';
            }
            next;
        }
        $regex .= quotemeta($character);
    }
    my $compiled = qr/^$regex$/s;
    $GLOB_REGEX_CACHE{$pattern} = $compiled;
    return $compiled;
}

sub fnmatchcase {
    my ( $path, $pattern ) = @_;
    return $path =~ fnmatch_pattern($pattern);
}

sub pure_parts {
    my ($path) = @_;
    my @parts  = grep { $_ ne '' && $_ ne '.' } split m{/}, $path;
    return @parts;
}

sub path_name {
    my ($path) = @_;
    my @parts = pure_parts($path);
    return @parts ? $parts[-1] : '';
}

sub path_parent_name {
    my ($path) = @_;
    my @parts = pure_parts($path);
    return $parts[-2] // '' if @parts >= 2;
    return '';
}

sub path_suffix {
    my ($path) = @_;
    my $name = path_name($path);
    return '' if $name eq '' || $name eq '.' || $name eq '..';
    my $index = rindex( $name, '.' );
    return '' if $index <= 0;
    return substr( $name, $index );
}

sub path_is_absolute {
    my ($path) = @_;
    return $path =~ m{^/};
}

sub path_has_parent_traversal {
    my ($path) = @_;
    return scalar grep { $_ eq '..' } pure_parts($path);
}

sub is_instruction {
    my ( $path, @extra_globs ) = @_;
    my $name = path_name($path);
    return 1 if $INSTRUCTION_NAMES{$name};
    for my $suffix (@INSTRUCTION_SUFFIXES) {
        return 1
          if length($name) >= length($suffix)
          && substr( $name, -length($suffix) ) eq $suffix;
    }
    my @parts       = pure_parts($path);
    my $parent_name = path_parent_name($path);
    return 1
      if $parent_name eq 'rules'
      && grep { $_ eq '.cursor' || $_ eq '.windsurf' || $_ eq '.continue' }
      @parts;
    return 1 if $path eq '.agents/skills/README.md';
    for my $glob (@extra_globs) {
        return 1 if fnmatchcase( $path, $glob );
    }
    return 0;
}

sub is_excluded {
    my ( $path, @patterns ) = @_;
    for my $pattern (@patterns) {
        return 1 if fnmatchcase( $path, $pattern );
    }
    return 0;
}

sub read_utf8 {
    my ($path) = @_;
    open my $handle, '<:raw', $path or die "$path: $!\n";
    local $/;
    my $bytes = <$handle>;
    close $handle;
    $bytes = '' unless defined $bytes;
    return decode( 'UTF-8', $bytes, FB_CROAK );
}

sub resolve_path {
    my ($path)   = @_;
    my $absolute = File::Spec->canonpath( File::Spec->rel2abs($path) );
    my $resolved = realpath($absolute);
    return $resolved if defined $resolved && $resolved ne '';
    my $parent = dirname($absolute);
    return $absolute if $parent eq $absolute;
    my $resolved_parent = resolve_path($parent);
    return File::Spec->catfile( $resolved_parent, basename($absolute) );
}

sub path_is_within {
    my ( $candidate, $root ) = @_;
    return 1 if $candidate eq $root;
    return 1 if index( $candidate, $root . '/' ) == 0;
    return 0;
}

sub unquote_path {
    my ($value) = @_;
    return $value unless $value =~ /%/;
    my @segments = split /(%[0-9A-Fa-f]{2})/, $value, -1;
    my $result   = '';
    my @bytes;
    my $flush = sub {
        return unless @bytes;
        $result .= decode( 'UTF-8', pack( 'C*', @bytes ), FB_DEFAULT );
        @bytes = ();
    };
    for my $segment (@segments) {
        if ( $segment =~ /^%([0-9A-Fa-f]{2})$/ ) {
            push @bytes, hex($1);
        }
        else {
            $flush->();
            $result .= $segment;
        }
    }
    $flush->();
    return $result;
}

sub split_url {
    my ($destination) = @_;
    my ( $scheme, $rest ) = ( '', $destination );
    if ( $rest =~ /^([A-Za-z][A-Za-z0-9+.-]*):/ ) {
        $scheme = $1;
        $rest   = substr( $rest, length($1) + 1 );
    }
    my $netloc = '';
    if ( $rest =~ m{^//} ) {
        $rest =~ s{^//}{};
        my ( $authority, $tail ) = split m{/}, $rest, 2;
        $netloc = defined $authority ? $authority  : '';
        $rest   = defined $tail      ? '/' . $tail : '';
    }
    my $path = $rest;
    $path =~ s/[?#].*$//s;
    return ( $scheme, $netloc, $path );
}

#
# Repository configuration.
#

sub default_config {
    return {
        exclude_paths            => [],
        instruction_globs        => [],
        required_headings        => {},
        required_phrases         => {},
        strict_text              => {},
        skill_reference_prefixes => [],
        inline_path_checks       => 0,
        minimum_changed_lines    => 1,
    };
}

sub config_error {
    my ($message) = @_;
    die "$CONFIG_NAME: $message\n";
}

sub is_plain_string {
    my ($value) = @_;
    return defined $value && !ref $value;
}

sub is_array_value {
    my ($value) = @_;
    return ref($value) eq 'ARRAY';
}

sub is_table_value {
    my ($value) = @_;
    return ref($value) eq 'HASH';
}

sub is_boolean_value {
    my ($value) = @_;
    return ref($value) eq 'AKV::Bool';
}

sub integer_value {
    my ($value) = @_;
    return AKV::Int::value($value)  if ref($value) eq 'AKV::Int';
    return AKV::Bool::value($value) if ref($value) eq 'AKV::Bool';
    return;
}

sub validate_relative_config_path {
    my ( $key, $path ) = @_;
    if ( path_is_absolute($path) || path_has_parent_traversal($path) ) {
        config_error("$key entries must be repository-relative: $path");
    }
    return;
}

sub parse_config {
    my ($root) = @_;
    my $path = "$root/$CONFIG_NAME";
    return default_config() unless -e $path;

    my $text = '';
    my $parsed;
    my $error;
    eval {
        $text   = read_utf8($path);
        $parsed = parse_toml($text);
    };
    if ($@) {
        $error = $@;
        $error =~ s/\s+$//;
        $error =~ s/^$CONFIG_NAME: //;
        config_error($error);
    }

    my @root_keys = grep { $_ ne 'validator' } keys %{$parsed};
    if (@root_keys) {
        config_error('only the [validator] table is supported');
    }
    my $settings = $parsed->{validator};
    $settings = {} unless defined $settings;
    if ( !is_table_value($settings) ) {
        config_error('[validator] must be a table');
    }

    my %allowed = map { $_ => 1 } (
        'contract_version',         'exclude_paths',
        'instruction_globs',        'required_headings',
        'required_phrases',         'strict_text',
        'skill_reference_prefixes', 'inline_path_checks',
        'minimum_changed_lines',
    );
    my @unknown = sort grep { !$allowed{$_} } keys %{$settings};
    if (@unknown) {
        config_error( 'unknown setting(s): ' . join( ', ', @unknown ) );
    }

    my $version = $settings->{contract_version};
    $version = $CONTRACT_VERSION unless defined $version;
    if ( !is_plain_string($version) || $version ne $CONTRACT_VERSION ) {
        config_error("contract_version must be '$CONTRACT_VERSION'");
    }

    my %parsed_config;
    for my $key ( 'exclude_paths', 'instruction_globs' ) {
        my $items = $settings->{$key};
        $items = [] unless defined $items;
        if ( !is_array_value($items)
            || grep { !is_plain_string($_) || trim_text($_) eq '' } @{$items} )
        {
            config_error("$key must be an array of non-empty strings");
        }
        for my $item ( @{$items} ) {
            validate_relative_config_path( $key, $item );
        }
        $parsed_config{$key} = $items;
    }

    for my $key ( 'required_headings', 'required_phrases' ) {
        my $mapping = $settings->{$key};
        $mapping = {} unless defined $mapping;
        if ( !is_table_value($mapping) ) {
            config_error("$key must be a table of paths to arrays");
        }
        my %validated;
        for my $mapping_path ( keys %{$mapping} ) {
            if (   path_is_absolute($mapping_path)
                || path_has_parent_traversal($mapping_path) )
            {
                config_error(
                    "$key paths must be repository-relative: $mapping_path");
            }
            my $values = $mapping->{$mapping_path};
            if ( !is_array_value($values)
                || grep { !is_plain_string($_) || trim_text($_) eq '' }
                @{$values} )
            {
                config_error(
                    "$key.$mapping_path must be an array of non-empty strings");
            }
            $validated{$mapping_path} = $values;
        }
        $parsed_config{$key} = \%validated;
    }

    my $known_paths = {};
    for my $instruction_path (
        discover_instruction_files( $root, $parsed_config{instruction_globs} ) )
    {
        $known_paths->{$instruction_path} = 1;
    }
    for my $key ( 'required_headings', 'required_phrases' ) {
        my @unknown_paths =
          sort grep { !$known_paths->{$_} } keys %{ $parsed_config{$key} };
        if (@unknown_paths) {
            config_error( "$key references unknown instruction path(s): "
                  . join( ', ', @unknown_paths ) );
        }
    }

    my $strict_text = $settings->{strict_text};
    $strict_text = {} unless defined $strict_text;
    if ( !is_table_value($strict_text) ) {
        config_error('strict_text must be a table');
    }
    my %allowed_text_rules = map { $_ => 1 } (
        'ascii_only',    'lf_only',
        'final_newline', 'no_trailing_whitespace',
        'no_nul',
    );
    my %parsed_strict;
    for my $pattern ( keys %{$strict_text} ) {
        if ( path_is_absolute($pattern) || path_has_parent_traversal($pattern) )
        {
            config_error("invalid strict_text pattern: $pattern");
        }
        my $rules = $strict_text->{$pattern};
        if ( !is_array_value($rules)
            || grep { !is_plain_string($_) || !$allowed_text_rules{$_} }
            @{$rules} )
        {
            config_error("strict_text.$pattern has an unknown rule");
        }
        $parsed_strict{$pattern} = $rules;
    }
    $parsed_config{strict_text} = \%parsed_strict;

    my $prefixes = $settings->{skill_reference_prefixes};
    $prefixes = [] unless defined $prefixes;
    if ( !is_array_value($prefixes)
        || grep { !is_plain_string($_) || $_ eq '' } @{$prefixes} )
    {
        config_error('skill_reference_prefixes must be an array');
    }
    $parsed_config{skill_reference_prefixes} = $prefixes;

    my $inline_checks = $settings->{inline_path_checks};
    $inline_checks = toml_boolean(0) unless defined $inline_checks;
    if ( !is_boolean_value($inline_checks) ) {
        config_error('inline_path_checks must be a boolean');
    }
    $parsed_config{inline_path_checks} = $inline_checks->value();

    my $minimum_lines = $settings->{minimum_changed_lines};
    $minimum_lines = toml_integer(1) unless defined $minimum_lines;
    my $minimum_value = integer_value($minimum_lines);
    if (   !defined $minimum_value
        || $minimum_value < 1
        || $minimum_value > 1000 )
    {
        config_error('minimum_changed_lines must be an integer from 1 to 1000');
    }
    $parsed_config{minimum_changed_lines} = $minimum_value;

    return \%parsed_config;
}

#
# Change discovery and instruction analysis.
#

sub parse_name_status {
    my ($raw)  = @_;
    my @fields = split /\x00/, $raw, -1;
    my @changes;
    my $index = 0;
    while ( $index + 1 < @fields ) {
        my $status = $fields[$index];
        my $path   = $fields[ $index + 1 ];
        $index += 2;
        if ( $status ne '' && $path ne '' ) {
            push @changes,
              {
                status => substr( $status, 0, 1 ),
                path   => $path,
              };
        }
    }
    return @changes;
}

sub deduplicate_changes {
    my (@changes) = @_;
    my %by_path;
    for my $change (@changes) {
        $by_path{ $change->{path} } = $change;
    }
    return map { $by_path{$_} } sort keys %by_path;
}

sub discover_changes {
    my ( $root, $scope, $base, $head ) = @_;
    if ( $scope eq 'worktree' ) {
        my $tracked =
          run_git( $root, 'diff', '--name-status', '-z', '--no-renames',
            'HEAD' );
        my @changes = parse_name_status($tracked);
        my $untracked =
          run_git( $root, 'ls-files', '--others', '--exclude-standard', '-z' );
        push @changes, map { { status => 'A', path => $_ } }
          grep { $_ ne '' } split /\x00/, $untracked, -1;
        return deduplicate_changes(@changes);
    }
    die "range scope requires base and head\n"
      unless defined $base && defined $head;
    my $base_commit = resolve_commit( $root, $base );
    my $head_commit = resolve_commit( $root, $head );
    my $merge_base =
      trim_text( run_git( $root, 'merge-base', $base_commit, $head_commit ) );
    my $raw = run_git( $root, 'diff', '--name-status', '-z', '--no-renames',
        $merge_base, $head_commit );
    return deduplicate_changes( parse_name_status($raw) );
}

sub changed_content {
    my ( $root, $scope, $base, $head, $path ) = @_;
    my $diff;
    if ( $scope eq 'range' ) {
        die "range scope requires base and head\n"
          unless defined $base && defined $head;
        my $base_commit = resolve_commit( $root, $base );
        my $head_commit = resolve_commit( $root, $head );
        my $merge_base =
          trim_text(
            run_git( $root, 'merge-base', $base_commit, $head_commit ) );
        $diff = run_git( $root, 'diff', '--no-ext-diff', '--unified=0',
            $merge_base, $head_commit, '--', $path );
    }
    else {
        $diff = run_git( $root, 'diff', '--no-ext-diff', '--unified=0',
            'HEAD', '--', $path );
    }

    my ( @added, @removed );
    for my $line ( split_text_lines($diff) ) {
        next if $line =~ /^(?:\+\+\+|---)/;
        if ( $line =~ /^\+(.*)$/s ) {
            my $normalized = normalize_knowledge_line($1);
            push @added, $normalized if $normalized ne '';
        }
        elsif ( $line =~ /^-(.*)$/s ) {
            my $normalized = normalize_knowledge_line($1);
            push @removed, $normalized if $normalized ne '';
        }
    }

    if ( $scope eq 'worktree' && $diff eq '' ) {
        my %changed = map { $_->{path} => 1 }
          discover_changes( $root, $scope, $base, $head );
        if ( $changed{$path} ) {
            my $candidate = "$root/$path";
            if ( -f $candidate ) {
                my ( $stdout, $stderr, $status ) =
                  run_git_optional( $root, 'ls-files', '--error-unmatch',
                    '--', $path );
                if ( $stdout eq '' ) {
                    my $content = eval { read_utf8($candidate) };
                    if ( defined $content ) {
                        for my $line ( split_text_lines($content) ) {
                            my $normalized = normalize_knowledge_line($line);
                            push @added, $normalized
                              if $normalized ne '';
                        }
                    }
                }
            }
        }
    }
    return ( \@added, \@removed );
}

sub normalize_knowledge_line {
    my ($line) = @_;
    my $content = $line;
    $content =~ s/^\s+//;
    $content =~ s/\s+$//;
    return '' if $content eq '';
    return ''
      if $content =~ /^#/
      || $content =~ /^<!--/
      || $content =~ /^-->/;
    return ''
      if $content =~
      /^(?:updated?|generated|last[ -]updated|date|updated_at)\s*[:=]/i;
    return '' if $content =~ /^[-*_`~>| ]+$/;
    $content              =~ s/\s+/ /g;
    $content              =~ s/^\s+//;
    $content              =~ s/\s+$//;
    return $content;
}

sub update_metrics {
    my ( $added, $removed ) = @_;
    my @remaining_added = @{$added};
    my @remaining_removed;
    for my $old ( @{$removed} ) {
        my $found = 0;
        for my $index ( 0 .. $#remaining_added ) {
            if ( $remaining_added[$index] eq $old ) {
                splice @remaining_added, $index, 1;
                $found = 1;
                last;
            }
        }
        push @remaining_removed, $old unless $found;
    }
    my @changed         = ( @remaining_added, @remaining_removed );
    my $effective_chars = 0;
    for my $line (@changed) {
        $line =~ s/[^A-Za-z0-9]//g;
        $effective_chars += length($line);
    }
    return ( scalar @changed, $effective_chars );
}

sub substantive_update {
    my ( $added, $removed, $minimum_lines ) = @_;
    my ( $line_count, $effective_chars ) = update_metrics( $added, $removed );
    return $line_count >= $minimum_lines && $effective_chars >= 24;
}

sub discover_instruction_files {
    my ( $root, $extra_globs ) = @_;
    my @found;
    my @pending = ('');

    while (@pending) {
        my $relative_directory = pop @pending;
        my $absolute_directory =
            $relative_directory eq ''
          ? $root
          : "$root/$relative_directory";
        opendir my $handle, $absolute_directory or next;
        my @entries = sort grep { $_ ne '.' && $_ ne '..' } readdir $handle;
        closedir $handle;

        my @directories;
        for my $entry (@entries) {
            my $absolute = "$absolute_directory/$entry";
            my $relative =
                $relative_directory eq ''
              ? $entry
              : "$relative_directory/$entry";
            if ( -l $absolute ) {
                next;
            }
            if ( -d $absolute ) {
                next if $entry eq '.git';
                push @directories, $relative;
                next;
            }
            if ( -f $absolute
                && is_instruction( $relative, @{$extra_globs} ) )
            {
                push @found, $relative;
            }
        }
        push @pending, reverse @directories;
    }
    my @sorted = sort @found;
    return @sorted;
}

sub parse_frontmatter_fields {
    my ($text) = @_;
    return
      unless $text =~ /\A---\s*\n(.*?)\n---\s*(?:\n|\z)/s;
    my $body = $1;
    my %fields;
    for my $line ( split_text_lines($body) ) {
        if ( $line =~ /^([A-Za-z0-9_-]+):\s*(.*?)\s*$/ ) {
            my ( $key, $value ) = ( $1, $2 );
            $value =~ s/^["']+//;
            $value =~ s/["']+$//;
            $fields{$key} = $value;
        }
    }
    return \%fields;
}

sub has_heading {
    my ( $text, $heading ) = @_;
    my $quoted = quotemeta($heading);
    return $text =~ /^##+\s+$quoted\s*$/m ? 1 : 0;
}

sub validate_structure {
    my ( $root, $paths, $required_headings, $required_phrases ) = @_;
    my @errors;
    for my $relative ( @{$paths} ) {
        my $text = eval { read_utf8("$root/$relative") };
        if ($@) {
            push @errors, [ $relative, 'cannot read UTF-8 instruction file' ];
            next;
        }
        if ( trim_text($text) eq '' ) {
            push @errors, [ $relative, 'instruction file is empty' ];
            next;
        }
        for my $heading ( @{ $required_headings->{$relative} // [] } ) {
            if ( !has_heading( $text, $heading ) ) {
                push @errors,
                  [ $relative, "missing configured section: $heading" ];
            }
        }
        for my $phrase ( @{ $required_phrases->{$relative} // [] } ) {
            my $normalized_text = $text;
            $normalized_text =~ s/\s+/ /g;
            my $normalized_phrase = $phrase;
            $normalized_phrase =~ s/\s+/ /g;
            if ( index( $normalized_text, $normalized_phrase ) < 0 ) {
                push @errors,
                  [ $relative, "missing configured policy text: $phrase" ];
            }
        }
        my $name = path_name($relative);
        if ( $name eq 'AGENTS.md' && $relative eq 'AGENTS.md' ) {
            if (
                !has_heading( $text, 'Continuous Agent & Skills Maintenance' ) )
            {
                push @errors,
                  [
                    $relative,
                    'missing Continuous Agent & Skills Maintenance section'
                  ];
            }
        }
        elsif ( $name eq 'SKILL.md' ) {
            my $fields = parse_frontmatter_fields($text);
            if ( !defined $fields ) {
                push @errors,
                  [
                    $relative,
                    'missing or malformed YAML frontmatter delimiters'
                  ];
            }
            else {
                for my $key ( 'name', 'description' ) {
                    my $value = $fields->{$key} // '';
                    if ( trim_text($value) eq '' ) {
                        push @errors,
                          [ $relative, "frontmatter requires non-empty $key" ];
                    }
                }
                my $field_name = $fields->{name} // '';
                if (   trim_text($field_name) ne ''
                    && trim_text($field_name) ne path_parent_name($relative) )
                {
                    push @errors,
                      [
                        $relative,
                        'frontmatter name must match the skill directory'
                      ];
                }
            }
            if ( !has_heading( $text, 'Maintenance & Continuous Learning' ) ) {
                push @errors,
                  [
                    $relative,
                    'missing Maintenance & Continuous Learning section'
                  ];
            }
        }
        elsif ( $name =~ /\.agent\.md$/ ) {
            if ( $text =~ /^---/ ) {
                my $fields = parse_frontmatter_fields($text);
                if ( !defined $fields ) {
                    push @errors,
                      [ $relative, 'malformed YAML frontmatter delimiters' ];
                }
                else {
                    my $field_name        = $fields->{name}        // '';
                    my $field_description = $fields->{description} // '';
                    if (   trim_text($field_name) eq ''
                        || trim_text($field_description) eq '' )
                    {
                        push @errors,
                          [
                            $relative,
                            'agent frontmatter requires name and description'
                          ];
                    }
                }
            }
            if (
                !has_heading( $text, 'Post-Change Knowledge Synchronization' ) )
            {
                push @errors,
                  [
                    $relative,
                    'missing Post-Change Knowledge Synchronization section'
                  ];
            }
        }
    }
    return @errors;
}

sub validate_extensions {
    my ( $root, $paths, $config, $skill_names ) = @_;
    my @errors;

    for my $relative ( @{$paths} ) {
        my $text = eval { read_utf8("$root/$relative") };
        next if $@;
        for my $pattern ( sort keys %{ $config->{strict_text} } ) {
            next unless fnmatchcase( $relative, $pattern );
            my %rules = map { $_ => 1 } @{ $config->{strict_text}{$pattern} };
            if ( $rules{lf_only} && $text =~ /\r/ ) {
                push @errors,
                  [ $relative,
                    'configured text rule requires LF line endings' ];
            }
            if (   $rules{final_newline}
                && $text ne ''
                && $text !~ /\n\z/ )
            {
                push @errors,
                  [ $relative,
                    'configured text rule requires a final newline' ];
            }
            if (   $rules{no_trailing_whitespace}
                && $text =~ /[\t ]+$/m )
            {
                push @errors,
                  [
                    $relative,
                    'configured text rule forbids trailing whitespace'
                  ];
            }
            if ( $rules{no_nul} && index( $text, "\x00" ) >= 0 ) {
                push @errors,
                  [ $relative, 'configured text rule forbids NUL bytes' ];
            }
            if ( $rules{ascii_only} && $text =~ /[^\x00-\x7f]/ ) {
                push @errors,
                  [ $relative, 'configured text rule requires ASCII text' ];
            }
        }
    }

    my @prefixes = @{ $config->{skill_reference_prefixes} };
    if (@prefixes) {
        for my $relative ( @{$paths} ) {
            next unless $relative =~ /\.agent\.md\z/;
            my $text = eval { read_utf8("$root/$relative") };
            next if $@;
            while ( $text =~ /`([^`]+)`/g ) {
                my $reference = $1;
                my $matches_prefix =
                  scalar grep { index( $reference, $_ ) == 0 } @prefixes;
                if ( $matches_prefix && !$skill_names->{$reference} ) {
                    push @errors,
                      [ $relative, "references missing skill: $reference" ];
                }
            }
        }
    }

    if ( $config->{inline_path_checks} ) {
        my %path_suffixes =
          map { $_ => 1 } ( '.md', '.pl', '.pm', '.t', '.8', '.ignore' );
        for my $relative ( @{$paths} ) {
            my $text = eval { read_utf8("$root/$relative") };
            next if $@;
            while ( $text =~ /`([^`]+)`/g ) {
                my $target = $1;
                next if $target =~ m{^/};
                next if $target =~ /\s/;
                my $suffix = path_suffix($target);
                next
                  unless $path_suffixes{$suffix}
                  || $target eq 'Makefile'
                  || $target eq 'LICENSE';
                my $parent_directory = dirname("$root/$relative");
                my $first_candidate  = "$parent_directory/$target";
                my $second_candidate = "$root/$target";

                if ( !-e $first_candidate && !-e $second_candidate ) {
                    push @errors,
                      [
                        $relative,
                        "inline repository path does not exist: $target"
                      ];
                }
            }
        }
    }
    return @errors;
}

sub validate_references {
    my ( $root, $paths ) = @_;
    my @errors;
    my $root_resolved = realpath($root);
    $root_resolved = abs_path($root) unless defined $root_resolved;
    $root_resolved = $root           unless defined $root_resolved;

    for my $relative ( @{$paths} ) {
        my $file_path = "$root/$relative";
        my $text      = eval { read_utf8($file_path) };
        next if $@;
        while ( $text =~ /(?<!!)\[[^\]]*\]\(([^)]+)\)/g ) {
            my $target = $1;
            $target =~ s/^\s+//;
            $target =~ s/\s+$//;
            my ($destination) = split /\s+/, $target, 2;
            next unless defined $destination;
            $destination =~ s/^<+//;
            $destination =~ s/>+$//;
            my ( $scheme, $netloc, $url_path ) = split_url($destination);
            next if $scheme ne '' || $netloc ne '';
            next if $url_path eq '';
            my $local_path = unquote_path($url_path);
            my $candidate;

            if ( $local_path =~ m{^/} ) {
                $local_path =~ s{^/+}{};
                $candidate = "$root/$local_path";
            }
            else {
                $candidate = dirname($file_path) . "/$local_path";
            }
            my $resolved = resolve_path($candidate);
            if ( !path_is_within( $resolved, $root_resolved ) ) {
                push @errors,
                  [
                    $relative,
                    "local reference escapes repository: $destination"
                  ];
                next;
            }
            if ( !-e $resolved ) {
                push @errors,
                  [ $relative, "broken local reference: $destination" ];
            }
        }
    }
    return @errors;
}

sub find_duplicate_or_conflicting {
    my ( $paths, $root ) = @_;
    my @duplicates;
    my @conflicts;
    my @by_content;
    my %content_index;

    for my $relative ( @{$paths} ) {
        my $text = eval { read_utf8("$root/$relative") };
        next if $@;
        my $normalized = $text;
        $normalized =~ s/\s+/ /g;
        $normalized =~ s/^\s+//;
        $normalized =~ s/\s+$//;
        if ( $normalized ne '' ) {
            if ( !exists $content_index{$normalized} ) {
                $content_index{$normalized} = scalar @by_content;
                push @by_content, [ $normalized, [] ];
            }
            push @{ $by_content[ $content_index{$normalized} ][1] }, $relative;
        }

        my %actions;
        my @action_order;
        for my $line ( split_text_lines($text) ) {
            my $prefix;
            my $modal;
            my $action_text;
            next
              unless $line =~
/^\s*(?<prefix>.*?)\b(?<modal>must not|mustn't|must|should not|should|do not|don't|never|always)\b\s+(?<action>[^.!?]{12,})[.!?]?\s*$/i;
            $prefix      = $+{prefix} // '';
            $modal       = lc( $+{modal} // '' );
            $action_text = lc( $prefix . ' ' . ( $+{action} // '' ) );
            $action_text =~ s/[^a-z0-9]+/ /g;
            $action_text =~ s/^\s+//;
            $action_text =~ s/\s+$//;
            next if length($action_text) < 12;
            my $polarity =
              (      $modal eq 'must not'
                  || $modal eq "mustn't"
                  || $modal eq 'should not'
                  || $modal eq 'do not'
                  || $modal eq "don't"
                  || $modal eq 'never' )
              ? 'negative'
              : 'positive';

            if ( !exists $actions{$action_text} ) {
                push @action_order, $action_text;
                $actions{$action_text} = {};
            }
            $actions{$action_text}{$polarity} = 1;
        }
        for my $action (@action_order) {
            my $polarities = $actions{$action};
            if ( $polarities->{negative} && $polarities->{positive} ) {
                push @conflicts,
                  "$relative: explicitly opposite directives for '$action'";
            }
        }
    }

    for my $group (@by_content) {
        my @files = sort @{ $group->[1] };
        push @duplicates, join( ', ', @files ) if @files > 1;
    }
    return ( \@duplicates, \@conflicts );
}

#
# Rule assembly and reporting.
#

sub make_result {
    my ( $rule_id, $status, $message, $files, $remediation ) = @_;
    $files = [] unless defined $files;
    my %seen;
    my @sorted = sort grep { !$seen{$_}++ } @{$files};
    return {
        rule_id     => $rule_id,
        status      => $status,
        message     => $message,
        files       => \@sorted,
        remediation => $remediation,
    };
}

sub is_infrastructure_only {
    my (@paths) = @_;
    return 0 unless @paths;
    for my $path (@paths) {
        my $matched = 0;
        for my $pattern (@INFRASTRUCTURE_PATTERNS) {
            if ( fnmatchcase( $path, $pattern ) ) {
                $matched = 1;
                last;
            }
        }
        return 0 unless $matched;
    }
    return 1;
}

sub json_string {
    my ($value) = @_;
    return JSON::PP->new->ascii(0)->encode($value);
}

sub run_validation {
    my ( $arguments, $cwd ) = @_;
    my ( $root, $config, $changes, $instruction_paths );
    my $setup_error;
    eval {
        $root    = find_repository_root($cwd);
        $config  = parse_config($root);
        $changes = [
            discover_changes(
                $root,              $arguments->{scope},
                $arguments->{base}, $arguments->{head}
            )
        ];
        $instruction_paths =
          [ discover_instruction_files( $root, $config->{instruction_globs} ) ];
    };
    if ($@) {
        $setup_error = $@;
        $setup_error =~ s/\s+$//;
        my $failure = make_result(
            'AK005',
            'FAIL',
            'Invalid validator configuration or execution error',
            [],
            'Check the Git worktree, revisions, and validator configuration.',
        );
        my @checks = (
            make_result(
                'AK001', 'PASS', 'Agent knowledge synchronization',
                [], undef
            ),
            make_result(
                'AK002', 'PASS', 'Agent and skill structure',
                [], undef
            ),
            make_result(
                'AKX001', 'PASS', 'Configured repository-specific validations',
                [], undef
            ),
            make_result( 'AK003', 'PASS', 'Internal references', [], undef ),
            make_result(
                'AK004', 'PASS', 'Knowledge update relevance',
                [], undef
            ),
            $failure,
            make_result(
                'AK006', 'PASS',
                'No duplicate or conflicting instructions detected',
                [], undef
            ),
        );
        return ( \@checks, 2, $setup_error );
    }

    my @excluded   = ( @DEFAULT_EXCLUDED_PATHS, @{ $config->{exclude_paths} } );
    my @considered = grep { !is_excluded( $_->{path}, @excluded ) } @{$changes};
    my @changed_paths       = map { $_->{path} } @considered;
    my $infrastructure_only = is_infrastructure_only(@changed_paths);

    my @knowledge_changes;
    my @project_changes;
    for my $change (@considered) {
        my $path = $change->{path};
        if ( is_instruction( $path, @{ $config->{instruction_globs} } ) ) {
            push @knowledge_changes, $path if -f "$root/$path";
        }
        else {
            push @project_changes, $path;
        }
    }

    my ( @substantive_files, @suspicious_files );
    for my $path (@knowledge_changes) {
        my ( $added, $removed ) =
          changed_content( $root,
            $arguments->{scope}, $arguments->{base}, $arguments->{head},
            $path );
        if (
            substantive_update(
                $added, $removed, $config->{minimum_changed_lines}
            )
          )
        {
            push @substantive_files, $path;
        }
        else {
            push @suspicious_files, $path;
        }
    }

    my $sync;
    if ( !@considered || $infrastructure_only ) {
        $sync = make_result( 'AK001', 'PASS', 'Agent knowledge synchronization',
            [], undef );
    }
    elsif (@substantive_files) {
        $sync = make_result( 'AK001', 'PASS', 'Agent knowledge synchronized',
            \@substantive_files, undef );
    }
    else {
        $sync = make_result(
            'AK001',
            'FAIL',
            'Missing agent knowledge update',
            ( @project_changes ? \@project_changes : \@changed_paths ),
'Update a relevant AGENTS.md, agent instruction, or SKILL.md with substantive operational guidance.',
        );
    }

    my @structure_errors = validate_structure(
        $root, $instruction_paths,
        $config->{required_headings},
        $config->{required_phrases}
    );
    my ( $structure, @structure_detail );
    if (@structure_errors) {
        $structure = make_result(
            'AK002',
            'FAIL',
            'Invalid agent or skill structure',
            [ map { $_->[0] } @structure_errors ],
'Fix the required headings and simple frontmatter fields; frontmatter checks are partial and are not full YAML validation.',
        );
        @structure_detail = map { [ $_->[0], $_->[1] ] } @structure_errors;
    }
    else {
        $structure =
          make_result( 'AK002', 'PASS', 'Agent and skill structure valid',
            [], undef );
    }

    my %skill_names;
    for my $relative ( @{$instruction_paths} ) {
        next unless path_name($relative) eq 'SKILL.md';
        my $text = eval { read_utf8("$root/$relative") };
        next if $@;
        my $fields = parse_frontmatter_fields($text);
        next unless defined $fields;
        my $name = trim_text( $fields->{name} // '' );
        $skill_names{$name} = 1 if $name ne '';
    }
    my @extension_errors =
      validate_extensions( $root, $instruction_paths, $config, \%skill_names );
    my ( $extension, @extension_detail );
    if (@extension_errors) {
        $extension = make_result(
            'AKX001',
            'FAIL',
            'Configured repository-specific validation failed',
            [ map { $_->[0] } @extension_errors ],
'Correct the configured rule or update its documented repository-specific configuration.',
        );
        @extension_detail =
          map { [ 'AKX001', $_->[1] ] } @extension_errors;
    }
    else {
        $extension =
          make_result( 'AKX001', 'PASS',
            'Configured repository-specific validations passed',
            [], undef );
    }

    my @reference_errors = validate_references( $root, $instruction_paths );
    my ( $references, @reference_detail );
    if (@reference_errors) {
        $references = make_result(
            'AK003',
            'FAIL',
            'Broken internal references',
            [ map { $_->[0] } @reference_errors ],
            'Correct or remove the broken repository-relative Markdown link.',
        );
        @reference_detail =
          map { [ $_->[0], $_->[1] ] } @reference_errors;
    }
    else {
        $references = make_result( 'AK003', 'PASS',
            'Internal references valid', [], undef );
    }

    my $relevance;
    if (@suspicious_files) {
        $relevance = make_result(
            'AK004',
            'FAIL',
            'Suspicious knowledge update: no effective content change detected',
            \@suspicious_files,
'Replace cosmetic or metadata-only edits with substantive operational guidance.',
        );
    }
    elsif (@substantive_files) {
        $relevance = make_result(
            'AK004',
            'WARN',
            'Manual relevance review recommended',
            \@substantive_files,
'Confirm that the instruction update is relevant and reusable; automation cannot prove semantic correctness.',
        );
    }
    else {
        $relevance =
          make_result( 'AK004', 'PASS',
            'No suspicious knowledge update detected',
            [], undef );
    }

    my $configuration =
      make_result( 'AK005', 'PASS',
        'Validator configuration and execution valid',
        [], undef );

    my ( $duplicates, $conflicts ) =
      find_duplicate_or_conflicting( $instruction_paths, $root );
    my ( $conflict_result, @conflict_detail );
    if ( @{$duplicates} || @{$conflicts} ) {
        my @files;
        for my $group ( @{$duplicates} ) {
            push @files, split /, /, $group;
        }
        for my $item ( @{$conflicts} ) {
            my ($path) = split /:/, $item, 2;
            push @files, $path;
        }
        my @detail;
        if ( @{$duplicates} ) {
            push @detail,
              'exact duplicate files: ' . join( '; ', @{$duplicates} );
        }
        push @detail, @{$conflicts};
        $conflict_result = make_result(
            'AK006',
            'WARN',
            'Potential duplicate or conflicting instructions found',
            \@files,
'Review the listed instructions and consolidate or clarify only when their scopes truly overlap.',
        );
        @conflict_detail = map { [ 'AK006', $_ ] } @detail;
    }
    else {
        $conflict_result =
          make_result( 'AK006', 'PASS',
            'No duplicate or conflicting instructions detected',
            [], undef, );
    }

    my @details = (
        @structure_detail, @extension_detail,
        @reference_detail, @conflict_detail,
    );
    my @results = (
        $sync,      $structure,     $extension, $references,
        $relevance, $configuration, $conflict_result,
    );
    return ( \@results, 0, json_string( \@details ) );
}

sub make_report {
    my ($checks) = @_;
    my @errors =
      grep { $_->{status} eq 'FAIL' } @{$checks};
    my @warnings =
      grep { $_->{status} eq 'WARN' } @{$checks};
    return {
        schema_version   => $SCHEMA_VERSION,
        contract_version => $CONTRACT_VERSION,
        status           => ( @errors ? 'FAIL' : 'PASS' ),
        summary          => {
            errors   => scalar @errors,
            warnings => scalar @warnings,
        },
        checks   => $checks,
        errors   => \@errors,
        warnings => \@warnings,
    };
}

sub print_report {
    my ( $report, $output_format ) = @_;
    if ( $output_format eq 'json' ) {
        my $encoder =
          JSON::PP->new->canonical(1)
          ->pretty(1)
          ->indent_length(2)
          ->space_before(0)
          ->space_after(1)
          ->ascii(0);
        print $encoder->encode($report);
        return;
    }
    for my $check ( @{ $report->{checks} } ) {
        print '[', $check->{status}, '] ', $check->{rule_id}, ' - ',
          $check->{message}, "\n";
        if ( @{ $check->{files} } ) {
            print '  Files: ', join( ', ', @{ $check->{files} } ), "\n";
        }
        if ( defined $check->{remediation} && $check->{remediation} ne '' ) {
            print '  Action: ', $check->{remediation}, "\n";
        }
    }
    print "\nAgent Knowledge Validation\n";
    print 'Status: ',   $report->{status},            "\n";
    print 'Errors: ',   $report->{summary}{errors},   "\n";
    print 'Warnings: ', $report->{summary}{warnings}, "\n";
    return;
}

#
# Command line.
#

sub usage_error {
    my ($message) = @_;
    print STDERR "usage: $0 [-h] --scope {worktree,range} [--base BASE]\n",
      "       [--head HEAD] [--format {text,json}]\n";
    print STDERR "$0: error: $message\n";
    exit 2;
}

sub print_help {
    print <<"HELP";
usage: $0 [-h] --scope {worktree,range} [--base BASE]
       [--head HEAD] [--format {text,json}]

Validate Agent Knowledge contract $CONTRACT_VERSION using only Perl's standard library.

options:
  -h, --help            show this help message and exit
  --scope {worktree,range}
  --base BASE           base Git revision; required with --scope range
  --head HEAD           head Git revision; required with --scope range
  --format {text,json}
HELP
    exit 0;
}

sub parse_arguments {
    my %arguments = ( format => 'text' );
    my $index     = 0;
    while ( $index < @ARGV ) {
        my $argument = $ARGV[$index];
        $index++;
        if ( $argument eq '-h' || $argument eq '--help' ) {
            print_help();
        }
        my ( $name, $inline_value ) = ( $argument, undef );
        if ( $argument =~ /^(--[^=]+)=(.*)$/ ) {
            ( $name, $inline_value ) = ( $1, $2 );
        }
        if (   $name eq '--scope'
            || $name eq '--base'
            || $name eq '--head'
            || $name eq '--format' )
        {
            my $value;
            if ( defined $inline_value ) {
                $value = $inline_value;
            }
            elsif ( $index < @ARGV ) {
                $value = $ARGV[$index];
                $index++;
            }
            else {
                usage_error("argument $name: expected one argument");
            }
            if ( $name eq '--scope' ) {
                usage_error("argument --scope: invalid choice: '$value'")
                  unless $value eq 'worktree' || $value eq 'range';
                $arguments{scope} = $value;
            }
            elsif ( $name eq '--format' ) {
                usage_error("argument --format: invalid choice: '$value'")
                  unless $value eq 'text' || $value eq 'json';
                $arguments{format} = $value;
            }
            elsif ( $name eq '--base' ) {
                $arguments{base} = $value;
            }
            else {
                $arguments{head} = $value;
            }
            next;
        }
        usage_error("unrecognized arguments: $argument");
    }

    usage_error('the following arguments are required: --scope')
      unless defined $arguments{scope};
    if ( $arguments{scope} eq 'range' ) {
        if (   !defined $arguments{base}
            || $arguments{base} eq ''
            || !defined $arguments{head}
            || $arguments{head} eq '' )
        {
            usage_error('--scope range requires both --base and --head');
        }
    }
    elsif ( defined $arguments{base} || defined $arguments{head} ) {
        usage_error('--base and --head are only valid with --scope range');
    }
    return \%arguments;
}

sub main {
    my $arguments = parse_arguments();
    binmode STDOUT, ':encoding(UTF-8)';
    binmode STDERR, ':encoding(UTF-8)';
    my ( $checks, $execution_code, $detail ) =
      run_validation( $arguments, getcwd() );
    my $report = make_report($checks);
    print_report( $report, $arguments->{format} );
    if ( $execution_code == 2 ) {
        if ( $arguments->{format} eq 'json' ) {
            print STDERR "validator execution error: $detail\n";
        }
        return 2;
    }
    return $report->{status} eq 'FAIL' ? 1 : 0;
}

exit main();
