# RealmAttrAuthen
set all_graphs {
  tac_plus-ng/RealmAttrAuthen
  {or
    {line
      'aaa 'realm '= realmName
    }
    {line
      'authentication-fallback
      {
        or
        {line
          '=
          {or
            'permit 'deny
          }
        }
        {line
          'period '= seconds
        }
      }
    }
    {line
      'anonymous-enable '=
      {or
        'yes 'no
      }
    }
    {line
      'augmented-enable '=
      {or
        'yes 'no
      }
    }
    {line
      'group 'realm '= realmName
    }
    {line
      'password
      {or
        {line
          'max-attempts '= count
        }
        {line
          'backoff '= seconds
        }
        {line
          'acl '= acl
        }
      }
    }
    {line
      'max-rounds '= count
    }
    {line
      'login 'backend '= 'mavis
      {stack
        {optx
          'prefetch
        }
        {optx
          'chalresp
          {optx
            'noecho
          }
        }
        {optx
          'chpass
        }
      }
    }
    {line
      'pap 'backend '= 'mavis
    }
    {line
      'pap 'password
      {or
        {optx
          'default
        }
        'mapping
      }
      '=
      {or
        'login 'pap
      }
    }
    {line
      'mschap 'backend '= 'mavis
    }
    {line
      'user 'backend '= 'mavis
      {optx
        'prefetch
      }
    }
  }
}
