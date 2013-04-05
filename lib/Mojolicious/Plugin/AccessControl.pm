package Mojolicious::Plugin::AccessControl;
use strict;
use warnings;
our $VERSION = '0.01';

use Mojo::Base 'Mojolicious::Plugin';
use Carp ();
use Net::CIDR::Lite;

sub register {
    my ( $self, $app ) = @_;
    $app->routes->add_condition(
        access => \&_access_control,
    );
}

sub _access_control {
    my ( $r, $c, $cap, $args ) = @_;

    for ( my $i = 0; $i < @$args; $i += 2 ) {
        my ( $allowing, $rule ) = ( $args->[$i], $args->[ $i + 1 ] );
        Carp::croak "must be allow or deny"
            unless $allowing =~ /^(allow|deny)$/;

        $allowing = ( $allowing eq 'allow' ) ? 1 : 0;

        if ( $rule eq 'all' ) {
            return $allowing;
        }
        elsif ( $rule =~ /[A-Z]$/i ) {
            my $host = $c->req->env->{'REMOTE_HOST'};
            return $allowing
                if ( defined $host && $host =~ /^(.*\.)?\Q${rule}\E$/ );
        }
        elsif ( ref($rule) eq 'CODE' ) {
            my $res = $rule->($c);
            return $allowing if ( defined $res && $res );
        }
        else {
            my @ip    = ref $rule ? @$rule : ($rule);
            my $cidr4 = Net::CIDR::Lite->new();
            my $cidr6 = Net::CIDR::Lite->new();
            for my $ip (@ip) {
                ( $ip =~ /:/ )
                    ? $cidr6->add_any($ip)
                    : $cidr4->add_any($ip);
            }
            my $addr = $c->tx->remote_address;
            if ( defined $addr ) {
                my $find_ip
                    = ( $addr =~ /:/ )
                    ? $cidr6->find($addr)
                    : $cidr4->find($addr);
                return $allowing if ($find_ip);
            }
        }
    }

    return 1; # allow
}

1;
__END__

=head1 NAME

Mojolicious::Plugin::AccessControl -

=head1 SYNOPSIS

  # Mojolicious
  sub stratup {
    my $self = shift;
    $self->plugin('AccessControl');
    ...
    ...
    ...
    my $r = $self->routes;
    $r->get('/')->to('example#welcome')->over( 'access' => [
        allow => 'allowhost.com',
        allow => ['127.0.0.1', '192.168.0.3', '192.168.0.5', '192.168.0.7'],
        deny  => '192.168.0.0/24',
        deny  => 'all',
    ] );
  }

  # Mojolicious::Lite
  plugin 'AccessControl';

  get '/' => sub {
    my $self = shift;
    $self->render('index');
  }, 'access' => [
      allow => 'allowhost.com',
      allow => ['127.0.0.1', '192.168.0.3', '192.168.0.5', '192.168.0.7'],
      deny  => '192.168.0.0/24',
      deny  => 'all',
  ];

=head1 DESCRIPTION

Mojolicious::Plugin::AccessControl is

=head1 AUTHOR

hayajo E<lt>hayajo@cpan.orgE<gt>

=head1 SEE ALSO

L<Mojolicious>, L<Plack::Middleware::Access>, L<Plack::Builder::Conditionals>,

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
