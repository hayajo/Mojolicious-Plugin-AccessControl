use Mojo::Base qw/-strict/;
use Mojolicious::Lite;

my %tests = (
    '/' => {
        rules => [],
        status => 200,
    },
    '/deny' => {
        rules => [ deny => '127.0.0.1' ],
        status => 404,
    },
    '/deny_all' => {
        rules => [ deny => 'all', allow => '127.0.0.1' ],
        status => 404,
    },
    '/only_127_0_0_1' => {
        rules => [ allow => '127.0.0.1', deny => 'all' ],
        status => 200,
    },
    '/deny_localhost' => {
        rules => [ deny => 'localhost' ],
        status => 404,
    },
    '/deny_by_code' => {
        rules => [ deny => sub { $_[0]->req->headers->user_agent =~ /Mojolicious/ } ],
        status => 404,
    },
    '/skip_resolve_hostname' => {
        rules => [
            allow => 'nosuchhost.com',
            allow => '127.0.0.1',
            deny  => 'all',
        ],
        status => 200,
    },
);

plugin 'AccessControl';

for my $pattern (keys %tests) {
    get $pattern => sub {
        $_[0]->render(text => $pattern);
    }, 'access' => $tests{$pattern}->{rules};
}

app->start;

use Test::Mojo;
use Test::More;

plan tests => scalar(keys %tests) * 2;

my $t = Test::Mojo->new();
$t->app->hook(
    before_dispatch => sub {
        $_[0]->req->env->{REMOTE_HOST} = 'localhost';
    }
);

for my $pattern (keys %tests) {
    diag "test:$pattern";
    $t->get_ok($pattern)->status_is($tests{$pattern}->{status});
}
