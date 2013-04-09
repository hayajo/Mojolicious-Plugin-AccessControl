package Mojolicious::Plugin::AccessControl::Static;
use strict;
use warnings;

use Mojo::Base 'Mojolicious::Plugin::AccessControl';
use Carp ();

sub register {
    my ( $self, $app ) = @_;

    no strict 'refs';
    no warnings 'once';
    *{'Mojolicious::Static::access'} = sub {
        my ($self, @args) = @_;
        return $self->{__access} unless (@args);
        my $opt
            = ( ref $args[0] eq 'HASH' )
            ? shift @args
            : {};
        $opt->{cache} = 1 unless ( defined $opt->{cache} );   # enabled caches
        Carp::croak 'Odd number of elements' if ( @args % 2 );
        $self->{__access} = { opt => $opt, rules => \@args };
    };

    # $app->helper( _accesscontrol_static => sub { state $cache = {} } );

    $app->hook(after_static => sub {
        my $c = shift;
        return unless ($c->res->code);

        my $conds
            = ( $c->app->static->access->{opt}->{cache} )
            # ? $c->_accesscontrol_static->{conds} ||= $self->_conds($c)
            ? $c->app->static->{__PACKAGE__ . '._conds'} ||= $self->_conds($c)
            : $self->_conds($c);

        my $path = $c->req->url->path->clone->canonicalize->to_string;
        for my $cond (@$conds) {
            my ($pattern, $opt, $rules) = @$cond;
            my $match
                    = ( ref $pattern eq 'Regexp' )
                    ? ( $path =~ $pattern )
                    : ( $path eq $pattern );
            next unless ($match);

            for my $rule ( @$rules ) {
                my ( $check, $allow ) = @{$rule};
                my $result = $check->($c);
                if ( defined $result && $result ) {
                    if ( !$allow && $opt->{on_deny} ) {
                        $opt->{on_deny}->($c);
                    }
                    else {
                        $c->render_not_found;
                    }
                    return;
                }
            }
        }
    });
}

sub _conds {
    my ($self, $c) = @_;
    my $global_opt = $c->app->static->access->{opt};
    my $rules      = $c->app->static->access->{rules};
    my @conds;
    for (my $i = 0; $i < @$rules; $i += 2) {
        my $pattern = $rules->[$i];
        my $args    = $rules->[ $i + 1 ];
        my ($opt, @remain)
            = ( ref $args->[0] eq 'HASH' )
            ? @$args
            : ({}, @$args);

        $opt->{on_deny} = $global_opt->{on_deny} unless ( defined $opt->{on_deny} );
        if ( $opt->{on_deny} && ref $opt->{on_deny} ne 'CODE' ) {
            Carp::croak "on_deny must be a CODEREF";
        }
        push @conds, [ $pattern, $opt, $self->_rules(@remain) ];
    }
    return \@conds;
}

1;
__END__

=head1 NAME

Mojolicious::Plugin::AccessControl::Static - Access control for static files

=head1 SYNOPSIS

  # Mojolicious
  sub stratup {
      my $self = shift;
      $self->plugin('AccessControl::Static');

      $self->static->access(
          '/local_only.txt' => [
              allow => 'allowhost.com',
              allow => '127.0.0.1'
              allow => '192.168.0.3',
              deny  => '192.168.0.0/24',
              deny  => 'all',
          ],
          qr{^/css/firefox_only} => [
              allow => sub { $_[0]->req->headers->user_agent =~ /Firefox/ },
              deny  => 'all',
          ],
      );

      # do something
  }

  # Mojolicious::Lite
  plugin 'AccessControl::Static';

  $app->static->access(
      { on_deny => sub {
          my $self = shift; # Mojolicious::Controller
          $self->res->code(403);
          $self->render( text => 'Forbidden' );
      } },
      '/local_only.txt' => [
          { on_deny => sub {
              $_[0]->render_not_found;
          } },
          allow => 'allowhost.com',
          allow => '127.0.0.1'
          allow => '192.168.0.3',
          deny  => '192.168.0.0/24',
          deny  => 'all',
      ],
      qr{^/css/firefox_only} => [
          allow => sub { $_[0]->req->headers->user_agent =~ /Firefox/ },
          deny  => 'all',
      ],
  );

  # do something

=head1 DESCRIPTION

Mojolicious::Plugin::AccessControl::Static is intended for restricting access to static files.

This plugin is B<EXPERIMENTAL>.

=head1 METHODS

L<Mojolicious::Plugin::AccessControl::Static> inherits all methods from L<Mojolicious::Plugin::AccessControl> and implements the following new ones.

=head1 ARGUMENTS

See L<Mojolicious::Plugin::AccessControl>

=head1 OPTIONS

See L<Mojolicious::Plugin::AccessControl>

=head1 AUTHOR

hayajo E<lt>hayajo@cpan.orgE<gt>

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides::Routing>, L<Plack::Middleware::Access>, L<Plack::Builder::Conditionals>,

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
