# NAME

Mojolicious::Plugin::AccessControl - Access control

# SYNOPSIS

    # Mojolicious
    sub stratup {
      my $self = shift;
      $self->plugin('AccessControl');
      my $r = $self->routes;
      $r->get('/')->to('example#welcome')->over( 'access' => [
          allow => 'allowhost.com',
          allow => '127.0.0.1',
          allow => '192.168.0.3',
          deny  => '192.168.0.0/24',
          allow => sub { $_[0]->req->headers->user_agent =~ /Firefox/ },
          deny  => 'all',
      ] )->name('index');
    }

    # Mojolicious::Lite
    plugin 'AccessControl';

    get '/' => ( 'access' => [
        allow => 'allowhost.com',
        allow => '127.0.0.1',
        allow => '192.168.0.3',
        deny  => '192.168.0.0/24',
        allow => sub { $_[0]->req->headers->user_agent =~ /Firefox/ },
        deny  => 'all',
    ] ) => sub {
        my $self = shift;
        # do something
    } => 'index';

    # if access was denined, run 'on_deny' which is a code reference.
    get '/deny_all' => ( 'access' => [
        { on_deny => sub {
            my $self = shift; # Mojolicious::Controller
            $self->res->code(403);
            $self->render( text => 'Forbidden' );
        } },
        deny  => 'all',
    ] ) => sub {
        my $self = shift;
        # do something
    } => 'index';

# DESCRIPTION

Mojolicious::Plugin::AccessControl is intended for restricting access to app routes.

This adds the condition to Mojolicious::Routes, which is named 'access'.

# METHODS

[Mojolicious::Plugin::AccessControl](http://search.cpan.org/perldoc?Mojolicious::Plugin::AccessControl) inherits all methods from [Mojolicious::Plugin](http://search.cpan.org/perldoc?Mojolicious::Plugin) and implements the following new ones.

## register

    $plugin->register(Mojolicious->new);

Register condition in [Mojolicious](http://search.cpan.org/perldoc?Mojolicious) application.

# ARGUMENTS

    get '/' => ( 'access' => [
        allow => 'allowhost.com',
        allow => '127.0.0.1',
        allow => '192.168.0.3',
        deny  => '192.168.0.0/24',
        allow => sub { $_[0]->req->headers->user_agent =~ /Firefox/ },
        deny  => 'all',
    ] ) => sub {
        my $self = shift;
        # do something
    } => 'index';

'access' takes an arrayref of rules.

Each rule consists of directive allow or deny and their argument. Rules are checked in the order of their record to the first match. Code rules always match if they return a defined non-zero value. Access is granted if no rule matched.

- "all"

    always matched.

- ip

    matches on one ip or ip range.

    See [Net::CIDR::Lite](http://search.cpan.org/perldoc?Net::CIDR::Lite).

- remote\_host

    matches on domain or subdomain of remote\_host if it can be resolved.

    If Mojo::Message::Request\#env->{REMOTE\_HOST} is not set, the rule is skipped.

- code

    an arbitrary code reference for checking arbitrary properties of the request.

    this function takes Mojolicious::Controller as parameter. The rule is skipped if the code returns undef.

# OPTIONS

'access' takes an arrayref of rules. If there is a hashref to the top, it considered options.

    get '/only_local' => ( 'access' => [
        # options
        {
          on_deny => sub {
              my $self = shift; # Mojolicious::Controller
              $self->res->code(403);
              $self->render( text => 'Forbidden' );
          },
        },
        # rules
        allow => '127.0.0.1',
        deny  => 'all',
    ] ) => sub {
        my $self = shift;
        # do something
    } => 'index';

- "on\_deny"

    an arbitrary code reference.

    if access was denied, run this callback.

# AUTHOR

hayajo <hayajo@cpan.org>

# CONTRIBUTORS

Many thanks to the contributors for their work.

- oliverguenther@github

# SEE ALSO

[Mojolicious](http://search.cpan.org/perldoc?Mojolicious), [Mojolicious::Guides::Routing](http://search.cpan.org/perldoc?Mojolicious::Guides::Routing), [Plack::Middleware::Access](http://search.cpan.org/perldoc?Plack::Middleware::Access), [Plack::Builder::Conditionals](http://search.cpan.org/perldoc?Plack::Builder::Conditionals),

# LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.
