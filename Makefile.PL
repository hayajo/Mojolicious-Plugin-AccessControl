use inc::Module::Install;
use Module::Install::Repository;
name 'Mojolicious-Plugin-AccessControl';
all_from 'lib/Mojolicious/Plugin/AccessControl.pm';

requires 'Mojolicious'     => '2.63';
requires 'Net::CIDR::Lite' => '0.21';

tests 't/*.t';
author_tests 'xt';

test_requires 'Test::More';
auto_set_repository;
auto_include;
WriteAll;
