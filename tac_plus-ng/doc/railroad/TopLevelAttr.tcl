# GlobalDecl
set all_graphs {
  tac_plus-ng/GlobalDecl
  {or
    {line
      'alias name '{ configuration-snippets  '}
    }
    
    {line
      'dns
      {or
        {line
          'address CIDR '= string
        }
        {line
          'prefetch 'file '= fileName
        }
      }
    }
    
    {line
      'proctitle '= string
    }
    
    {line
      'umask '= umask
    }
    
    {line
      'retire
      {or
        {line
          'limit '= count
        }
        {line
          'seconds '= seconds
        }
      }
    }
    
    {line
      'setenv name string
    }
    
    {line
      'syslog
      {or
        {line
          'level '=
          {or
            'EMERG others 'DEBUG
          }
        }
        {line
          'facility '=
          {or
            'AUTH others 'FTP
          }
        }
        {line
          'ident '= string
        }
        {line
          'default '= seconds
          {or
            'yes 'no
          }
        }
      }
    }
  }
}
