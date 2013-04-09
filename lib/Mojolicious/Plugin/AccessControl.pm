package Mojolicious::Plugin::AccessControl;
use strict;
use warnings;
our $VERSION = '0.01';

use Mojo::Base 'Mojolicious::Plugin';
use Net::CIDR::Lite;
use Carp ();

use constant CONDITION_NAME => 'access';

sub register {
    my ( $self, $app ) = @_;

    $app->routes->add_condition( CONDITION_NAME() => sub {
        my ( $r, $c, $cap, $args ) = @_;
        $args ||= [];

        my $opt
            = ( ref $args->[0] eq 'HASH' )
            ? shift @$args
            : {};
        $opt->{cache} = 1 unless ( defined $opt->{cache} ); # enabled caches

        if ( $opt->{on_deny} && ref $opt->{on_deny} ne 'CODE' ) {
            Carp::croak "on_deny must be a CODEREF";
        }

        my $rules
            = ( $opt->{cache} )
            ? ( $r->{__PACKAGE__ . '._rules'} ||= $self->_rules(@$args) ) # caches to Mojolicious::Routes::Route
            : $self->_rules(@$args);

        for my $rule ( @$rules ) {
            my ( $check, $allow ) = @{$rule};
            my $result = $check->($c);
            if ( defined $result && $result ) {
                if ( !$allow && $opt->{on_deny} ) {
                    $opt->{on_deny}->($c);
                }
                return $allow;
            }
        }

        return 1;
    } );
}

sub _rules {
    my ($self, @args) = @_;

    my @rules;
    for ( my $i = 0; $i < @args; $i += 2 ) {
        my ( $allowing, $rule ) = ( $args[$i], $args[ $i + 1 ] );
        Carp::croak "must be allow or deny"
            unless $allowing =~ /^(allow|deny)$/;

        $allowing = ( $allowing eq 'allow' ) ? 1 : 0;
        my $check = $rule;

        if ( $rule =~ /^ALL$/i ) {
            $check = sub { 1 };
        }
        elsif ( $rule =~ /[A-Z]$/i ) {
            $check = sub {
                my $host = $_[0]->req->env->{'REMOTE_HOST'};
                return unless defined $host; # skip
                return $host =~ /^(.*\.)?\Q${rule}\E$/;
            };
        }
        elsif ( ref($rule) ne 'CODE' ) {
            my $cidr = Net::CIDR::Lite->new();
            $cidr->add_any($rule);
            $check = sub {
                my $addr = $_[0]->tx->remote_address;
                if ( defined $addr ) {
                    return ( $cidr->find($addr) ) ? 1 : 0;
                }
            };
        }

        push @rules, [ $check => $allowing ];
    }

    return \@rules;
}

1;
__END__

=head1 NAME

Mojolicious::Plugin::AccessControl - Access control

=head1 SYNOPSIS

  # Mojolicious
  sub stratup {
    my $self = shift;
    $self->plugin('AccessControl');
    my $r = $self->routes;
    $r->get('/')->to('example#welcome')->over( 'access' => [
        allow => 'allowhost.com',
        allow => '127.0.0.1'
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

  # call 'on_deny' which is a code reference, if access was denined.
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

=head1 DESCRIPTION

Mojolicious::Plugin::AccessControl is intended for restricting access to app routes.

This adds the condition to Mojolicious::Routes, which is named 'access'.

=head1 METHODS

L<Mojolicious::Plugin::AccessControl> inherits all methods from L<Mojolicious::Plugin> and implements the following new ones.

=head2 register

  $plugin->register(Mojolicious->new);

Register condition in L<Mojolicious> application.

=head1 ARGUMENTS

'access' takes an arrayref of rules. Each rule consists of directive allow or deny and their argument. Rules are checked in the order of their record to the first match. Code rules always match if they return a defined non-zero value. Access is granted if no rule matched.

=over 2

=item "all"

always matched.

=item ip

matches on one ip or ip range.

See L<Net::CIDR::Lite>.

=item remote_host

matches on domain or subdomain of remote_host if it can be resolved.

If Mojo::Message::Request#env->{REMOTE_HOST} is not set, the rule is skipped.

=item code

an arbitrary code reference for checking arbitrary properties of the request.

this function takes Mojolicious::Controller as parameter. The rule is skipped if the code returns undef.

=back

=head1 AUTHOR

hayajo E<lt>hayajo@cpan.orgE<gt>

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides::Routing>, L<Plack::Middleware::Access>, L<Plack::Builder::Conditionals>,

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
