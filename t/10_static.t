use Mojo::Base qw/-strict/;
use Mojolicious::Lite;

my @tests = (
    '/foo.txt' => {
        rules => [],
        status => 200,
        content => "Hello World\n",
    },
    qr/\.css$/ => {
        url    => '/css/bar.css',
        rules  => [ deny => '127.0.0.1' ],
        status => 404,
    },
    qr{^/img/[^/]+$} => {
        url    => '/img/buz.png',
        rules => [
            {
                on_deny => sub {
                    my $self = shift;
                    $self->res->code(403);
                    $self->render(text => 'Forbidden');
                },
            },
            deny => '127.0.0.1'
        ],
        status => 403,
        content => 'Forbidden',
    },
    qr{^/img/[^/]+$} => {
        url    => '/img/allow/buz.png', # don't match
        rules => [ deny => '127.0.0.1' ],
        status => 200
    },
);

plugin 'AccessControl::Static';

my @conds;
for ( my $i = 0; $i < @tests; $i += 2 ) {
    my $pattern = $tests[$i];
    my $test    = $tests[ $i + 1 ];
    push @conds, $pattern => $test->{rules};
}

app->static->access(@conds);

app->start;

use Test::Mojo;
use Test::More;

my $t = Test::Mojo->new();
$t->app->hook(
    before_dispatch => sub {
        $_[0]->req->env->{REMOTE_HOST} = 'localhost';
    }
);

for ( my $i = 0; $i < @tests; $i += 2 ) {
    my $pattern = $tests[$i];
    my $test    = $tests[ $i + 1 ];
    my $url = $test->{url} || $pattern;
    diag "test:$url";
    $t->get_ok($url)->status_is($test->{status});
    if ( my $expect = $test->{content} ) {
        $t->content_is($expect);
    }
}

done_testing;
