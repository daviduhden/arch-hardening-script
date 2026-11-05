#!/usr/bin/env perl
#
# Black-box contract tests for validate-agent-knowledge.pl.
#
# See the LICENSE file at the top of the project tree for copyright
# and license details.

use strict;
use warnings;

use Cwd            qw(getcwd);
use Encode         qw(decode encode);
use File::Basename qw(dirname);
use File::Copy     qw(copy);
use File::Path     qw(make_path);
use File::Spec;
use File::Temp ();
use IO::Select;
use IPC::Open3 qw(open3);
use JSON::PP   ();
use Test::More;
use Symbol qw(gensym);

my $SOURCE_ROOT =
  File::Spec->rel2abs( File::Spec->catdir( dirname(__FILE__), '..', '..' ) );
my $VALIDATOR =
  File::Spec->catfile( $SOURCE_ROOT, 'scripts', 'validate-agent-knowledge.pl' );

my $AGENT_TEXT = <<'AGENT';
# Repository guidance

## Continuous Agent & Skills Maintenance

Keep operational guidance accurate and reusable.

See [the readme](README.md).
AGENT

my $SKILL_TEXT = <<'SKILL';
---
name: example
description: Guidance for the example subsystem.
---
# Example skill

## Maintenance & Continuous Learning

Keep the procedure current.
SKILL

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
            if ( !defined $count || $count == 0 ) {
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
    return (
        decode( 'UTF-8', $stdout, Encode::FB_DEFAULT() ),
        decode( 'UTF-8', $stderr, Encode::FB_DEFAULT() ),
        $? >> 8,
    );
}

sub git_in {
    my ( $repository, @arguments ) = @_;
    local $ENV{GIT_CONFIG_GLOBAL} = File::Spec->devnull;
    local $ENV{GIT_CONFIG_SYSTEM} = File::Spec->devnull;
    my ( $stdout, $stderr, $status ) =
      capture_command( 'git', '-c', 'commit.gpgsign=false',
        '-c', 'tag.gpgsign=false', '-C', $repository, @arguments, );
    return ( $stdout, $stderr, $status );
}

sub write_file {
    my ( $repository, $relative, $content ) = @_;
    my $path = File::Spec->catfile( $repository, split m{/}, $relative );
    make_path( dirname($path) ) unless -d dirname($path);
    open my $handle, '>:encoding(UTF-8)', $path
      or die "cannot write $path: $!";
    print {$handle} $content;
    close $handle;
    return;
}

sub read_file {
    my ($path) = @_;
    open my $handle, '<:encoding(UTF-8)', $path
      or die "cannot read $path: $!";
    local $/;
    my $content = <$handle>;
    close $handle;
    return defined $content ? $content : '';
}

sub new_repository {
    my $temporary  = File::Temp->newdir();
    my $repository = File::Spec->catdir( $temporary->dirname, 'repo' );
    mkdir $repository or die "cannot create $repository: $!";
    mkdir File::Spec->catdir( $repository, 'scripts' )
      or die "cannot create scripts: $!";
    copy(
        $VALIDATOR,
        File::Spec->catfile(
            $repository, 'scripts', 'validate-agent-knowledge.pl'
        )
    ) or die "cannot copy validator: $!";

    my ( $stdout, $stderr, $status ) =
      git_in( $repository, 'init', '-q', '-b', 'main' );
    die $stderr if $status;
    ( $stdout, $stderr, $status ) =
      git_in( $repository, 'config', 'user.name', 'Validator Test' );
    die $stderr if $status;
    ( $stdout, $stderr, $status ) =
      git_in( $repository, 'config', 'user.email',
        'validator@example.invalid' );
    die $stderr if $status;

    write_file( $repository, 'AGENTS.md',       $AGENT_TEXT );
    write_file( $repository, 'README.md',       "Repository fixture.\n" );
    write_file( $repository, 'src/example.txt', "VALUE = 1\n" );
    write_file( $repository, '.agents/skills/example/SKILL.md', $SKILL_TEXT );

    ( $stdout, $stderr, $status ) = git_in( $repository, 'add', '-A' );
    die $stderr if $status;
    ( $stdout, $stderr, $status ) =
      git_in( $repository, 'commit', '-q', '-m', 'baseline' );
    die $stderr if $status;
    ( $stdout, $stderr, $status ) = git_in( $repository, 'rev-parse', 'HEAD' );
    die $stderr if $status;
    my $base = $stdout;
    $base =~ s/^\s+//;
    $base =~ s/\s+$//;

    return {
        temporary => $temporary,
        repo      => $repository,
        base      => $base,
    };
}

sub git_ok {
    my ( $repository, @arguments ) = @_;
    my ( $stdout, $stderr, $status ) = git_in( $repository, @arguments );
    die $stderr if $status;
    return $stdout;
}

sub commit_all {
    my ( $repository, $message ) = @_;
    git_ok( $repository, 'add', '-A' );
    git_ok( $repository, 'commit', '-q', '-m', $message );
    return;
}

sub update_agent {
    my ($repository) = @_;
    my $path = File::Spec->catfile( $repository, 'AGENTS.md' );
    write_file( $repository, 'AGENTS.md',
        read_file($path)
          . "\nWhen parser boundaries change, update examples and rerun compatibility review.\n"
    );
    return;
}

sub run_validator {
    my ( $repository, @arguments ) = @_;
    return run_validator_in( $repository, $repository, @arguments );
}

sub run_validator_in {
    my ( $repository, $working_directory, @arguments ) = @_;
    local $ENV{GIT_CONFIG_GLOBAL} = File::Spec->devnull;
    local $ENV{GIT_CONFIG_SYSTEM} = File::Spec->devnull;
    my $previous = getcwd();
    chdir $working_directory or die "cannot chdir to $working_directory: $!";
    my @result = capture_command(
        $^X,
        File::Spec->catfile(
            $repository, 'scripts', 'validate-agent-knowledge.pl'
        ),
        @arguments,
    );
    chdir $previous or die "cannot restore cwd: $!";
    return {
        stdout => $result[0],
        stderr => $result[1],
        status => $result[2],
    };
}

sub test_clean_worktree_passes {
    my $fixture = new_repository();
    my $result  = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 0, $result->{stdout} . $result->{stderr} );
    like( $result->{stdout}, qr/Status: PASS/, 'clean worktree reports PASS' );
    like( $result->{stdout}, qr/Errors: 0/,    'clean worktree has no errors' );
}

sub test_code_change_without_knowledge_update_fails {
    my $fixture = new_repository();
    write_file( $fixture->{repo}, 'src/example.txt', "VALUE = 2\n" );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 1, 'code change without knowledge update exits 1' );
    like( $result->{stdout}, qr/\[FAIL\] AK001/, 'AK001 fails' );
}

sub test_code_change_with_agents_update_passes_with_review_warning {
    my $fixture = new_repository();
    write_file( $fixture->{repo}, 'src/example.txt', "VALUE = 2\n" );
    update_agent( $fixture->{repo} );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 0, $result->{stdout} . $result->{stderr} );
    like( $result->{stdout}, qr/\[PASS\] AK001/, 'AK001 passes' );
    like(
        $result->{stdout},
        qr/\[WARN\] AK004/,
        'AK004 requests manual review'
    );
}

sub test_code_change_with_skill_update_passes {
    my $fixture = new_repository();
    write_file( $fixture->{repo}, 'src/example.txt', "VALUE = 2\n" );
    my $skill_path =
      File::Spec->catfile( $fixture->{repo}, '.agents', 'skills', 'example',
        'SKILL.md' );
    write_file( $fixture->{repo}, '.agents/skills/example/SKILL.md',
        read_file($skill_path)
          . "\nWhen this parser changes, retain compatibility examples in this skill.\n"
    );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 0, $result->{stdout} . $result->{stderr} );
}

sub test_cosmetic_knowledge_change_fails_ak001_and_ak004 {
    my $fixture = new_repository();
    my $path    = File::Spec->catfile( $fixture->{repo}, 'AGENTS.md' );
    my $text    = read_file($path);
    $text =~ s/operational guidance/operational  guidance/;
    write_file( $fixture->{repo}, 'AGENTS.md', $text );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 1, 'cosmetic knowledge change exits 1' );
    like( $result->{stdout}, qr/\[FAIL\] AK004/, 'AK004 fails' );
}

sub test_malformed_skill_fails_ak002 {
    my $fixture = new_repository();
    write_file( $fixture->{repo}, 'src/example.txt', "VALUE = 2\n" );
    update_agent( $fixture->{repo} );
    write_file(
        $fixture->{repo},
        '.agents/skills/example/SKILL.md',
        "---\nname: example\n---\n# Broken\n"
    );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 1, 'malformed skill exits 1' );
    like( $result->{stdout}, qr/\[FAIL\] AK002/, 'AK002 fails' );
}

sub test_broken_internal_reference_fails_ak003 {
    my $fixture = new_repository();
    update_agent( $fixture->{repo} );
    my $path = File::Spec->catfile( $fixture->{repo}, 'AGENTS.md' );
    write_file( $fixture->{repo}, 'AGENTS.md',
        read_file($path) . "\nSee [missing](docs/missing.md).\n" );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 1, 'broken local link exits 1' );
    like( $result->{stdout}, qr/\[FAIL\] AK003/, 'AK003 fails' );
}

sub test_untracked_project_file_is_discovered {
    my $fixture = new_repository();
    write_file( $fixture->{repo}, 'src/new.txt', "VALUE = 3\n" );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 1, 'untracked project file exits 1' );
    like( $result->{stdout}, qr/src\/new\.txt/,
        'untracked project file is listed' );
}

sub test_renamed_project_file_is_discovered {
    my $fixture = new_repository();
    git_ok( $fixture->{repo}, 'mv', 'src/example.txt', 'src/renamed.txt' );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 1, 'renamed project file exits 1' );
    like( $result->{stdout}, qr/\[FAIL\] AK001/, 'AK001 fails for rename' );
}

sub test_deleted_project_file_is_discovered {
    my $fixture = new_repository();
    unlink File::Spec->catfile( $fixture->{repo}, 'src', 'example.txt' )
      or die "cannot delete fixture file: $!";
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 1, 'deleted project file exits 1' );
    like( $result->{stdout}, qr/src\/example\.txt/,
        'deleted project file is listed' );
}

sub test_staged_and_unstaged_changes_are_combined {
    my $fixture = new_repository();
    write_file( $fixture->{repo}, 'src/example.txt', "VALUE = 2\n" );
    git_ok( $fixture->{repo}, 'add', 'src/example.txt' );
    update_agent( $fixture->{repo} );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 0, $result->{stdout} . $result->{stderr} );
}

sub test_valid_range_uses_base_and_head {
    my $fixture = new_repository();
    write_file( $fixture->{repo}, 'src/example.txt', "VALUE = 2\n" );
    update_agent( $fixture->{repo} );
    commit_all( $fixture->{repo}, 'code and knowledge' );
    my $head = git_ok( $fixture->{repo}, 'rev-parse', 'HEAD' );
    $head =~ s/^\s+//;
    $head =~ s/\s+$//;
    my $result = run_validator( $fixture->{repo}, '--scope', 'range',
        '--base', $fixture->{base}, '--head', $head, );
    is( $result->{status}, 0, $result->{stdout} . $result->{stderr} );
}

sub test_missing_revision_returns_execution_error {
    my $fixture = new_repository();
    my $result  = run_validator( $fixture->{repo}, '--scope', 'range',
        '--base', 'missing', '--head', 'HEAD', );
    is( $result->{status}, 2, 'missing revision exits 2' );
    like( $result->{stdout}, qr/\[FAIL\] AK005/, 'AK005 fails' );
}

sub test_invalid_configuration_returns_execution_error {
    my $fixture = new_repository();
    write_file(
        $fixture->{repo},
        '.agent-knowledge-validator.toml',
        "[validator]\ncontract_version = \"9.9.9\"\n"
    );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 2, 'invalid contract version exits 2' );
    like( $result->{stdout}, qr/\[FAIL\] AK005/, 'AK005 fails' );
}

sub test_malformed_toml_returns_execution_error {
    my $fixture = new_repository();
    write_file(
        $fixture->{repo},
        '.agent-knowledge-validator.toml',
        "[validator\ncontract_version = \"1.0.0\"\n"
    );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 2, 'malformed TOML exits 2' );
    like( $result->{stdout}, qr/\[FAIL\] AK005/, 'AK005 fails for TOML' );
}

sub test_incompatible_cli_arguments_return_usage_error {
    my $fixture = new_repository();
    my $result  = run_validator( $fixture->{repo}, '--scope', 'range', '--base',
        $fixture->{base} );
    is( $result->{status}, 2, 'incomplete range CLI exits 2' );
    like(
        $result->{stderr},
        qr/requires both --base and --head/,
        'range requires both revisions'
    );
}

sub test_help_uses_standard_argument_documentation {
    my $fixture = new_repository();
    my $result  = run_validator( $fixture->{repo}, '--help' );
    is( $result->{status}, 0, 'help exits 0' );
    like(
        $result->{stdout},
        qr/--scope \{worktree,range\}/,
        'help documents scope choices'
    );
    like(
        $result->{stdout},
        qr/--format \{text,json\}/,
        'help documents format choices'
    );
}

sub test_outside_git_repository_returns_execution_error {
    my $fixture = new_repository();
    my $outside =
      File::Spec->catdir( $fixture->{temporary}->dirname, 'outside' );
    mkdir $outside or die "cannot create $outside: $!";
    my $result =
      run_validator_in( $fixture->{repo}, $outside, '--scope', 'worktree' );
    is( $result->{status}, 2, 'outside repository exits 2' );
    like( $result->{stdout}, qr/\[FAIL\] AK005/, 'AK005 fails outside Git' );
}

sub test_json_output_is_machine_readable {
    my $fixture = new_repository();
    my $result =
      run_validator( $fixture->{repo}, '--scope', 'worktree', '--format',
        'json' );
    is( $result->{status}, 0, $result->{stderr} );
    my $report = eval { JSON::PP::decode_json( $result->{stdout} ) };
    ok( defined $report, 'JSON output decodes' );
    is( $report->{schema_version},     '1.0',   'schema version is stable' );
    is( $report->{contract_version},   '1.0.0', 'contract version is stable' );
    is( $report->{status},             'PASS',  'JSON status is PASS' );
    is( scalar @{ $report->{checks} }, 7, 'JSON report has seven checks' );
}

sub test_explicit_exclusion_does_not_trigger_ak001 {
    my $fixture = new_repository();
    write_file( $fixture->{repo}, '.agent-knowledge-validator.toml',
            "[validator]\n"
          . "contract_version = \"1.0.0\"\n"
          . "exclude_paths = [\"generated/**\"]\n" );
    commit_all( $fixture->{repo}, 'configure generated path exclusion' );
    write_file( $fixture->{repo}, 'generated/output.txt',
        "Generated output.\n" );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 0, $result->{stdout} . $result->{stderr} );
}

sub test_nested_configuration_tables_are_supported {
    my $fixture = new_repository();
    write_file( $fixture->{repo}, '.agent-knowledge-validator.toml',
            "[validator]\n"
          . "contract_version = \"1.0.0\"\n"
          . "minimum_changed_lines = 1\n"
          . "[validator.required_headings]\n"
          . "\"AGENTS.md\" = [\"Continuous Agent & Skills Maintenance\"]\n"
          . "[validator.required_phrases]\n"
          . "\"AGENTS.md\" = [\"Keep operational guidance accurate and reusable.\"]\n"
          . "[validator.strict_text]\n"
          . "\"AGENTS.md\" = [\"lf_only\", \"final_newline\", \"ascii_only\",]\n"
    );
    commit_all( $fixture->{repo}, 'configure nested validation tables' );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 0, $result->{stdout} . $result->{stderr} );
}

sub test_conflicting_directives_are_reported {
    my $fixture = new_repository();
    my $path    = File::Spec->catfile( $fixture->{repo}, 'AGENTS.md' );
    write_file( $fixture->{repo}, 'AGENTS.md',
            read_file($path)
          . "\nOperators must retain exclusive control of validation results.\n"
          . "Operators must not retain exclusive control of validation results.\n"
    );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 0, $result->{stdout} . $result->{stderr} );
    like(
        $result->{stdout},
        qr/\[WARN\] AK006/,
        'AK006 reports conflicting directives'
    );
}

test_clean_worktree_passes();
test_code_change_without_knowledge_update_fails();
test_code_change_with_agents_update_passes_with_review_warning();
test_code_change_with_skill_update_passes();
test_cosmetic_knowledge_change_fails_ak001_and_ak004();
test_malformed_skill_fails_ak002();
test_broken_internal_reference_fails_ak003();
test_untracked_project_file_is_discovered();
test_renamed_project_file_is_discovered();
test_deleted_project_file_is_discovered();
test_staged_and_unstaged_changes_are_combined();
test_valid_range_uses_base_and_head();
test_missing_revision_returns_execution_error();
test_invalid_configuration_returns_execution_error();
test_malformed_toml_returns_execution_error();
test_incompatible_cli_arguments_return_usage_error();
test_help_uses_standard_argument_documentation();
test_outside_git_repository_returns_execution_error();
test_json_output_is_machine_readable();
test_explicit_exclusion_does_not_trigger_ak001();
test_nested_configuration_tables_are_supported();
test_conflicting_directives_are_reported();

sub test_path_with_spaces_and_special_characters_is_discovered {
    my $fixture = new_repository();
    my $path    = 'src/new file [draft] (1).txt';
    write_file( $fixture->{repo}, $path, "VALUE = 3\n" );
    my $result = run_validator( $fixture->{repo}, '--scope', 'worktree' );
    is( $result->{status}, 1, 'special-character path exits 1' );
    like( $result->{stdout}, qr/\Q$path\E/,
        'special-character path is listed' );
}

sub test_repeated_validation_is_idempotent {
    my $fixture = new_repository();
    my $first =
      run_validator( $fixture->{repo}, '--scope', 'worktree', '--format',
        'json' );
    my $second =
      run_validator( $fixture->{repo}, '--scope', 'worktree', '--format',
        'json' );
    is( $first->{status}, $second->{status}, 'repeated status is stable' );
    is( $first->{stdout}, $second->{stdout}, 'repeated stdout is stable' );
    is( $first->{stderr}, $second->{stderr}, 'repeated stderr is stable' );
}
test_path_with_spaces_and_special_characters_is_discovered();
test_repeated_validation_is_idempotent();

done_testing();
