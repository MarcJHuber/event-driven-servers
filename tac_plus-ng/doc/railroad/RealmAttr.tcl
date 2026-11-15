# RealmAttr
set all_graphs {
  tac_plus-ng/RealmAttr
  {toploop
    {or
      {line
        MavisDecl
      }
      {line
        'warning 'period '= days
      }
      {line
        'single-connect '=
        {or
          'yes 'no
        }
      }
      {line
        'mavis 'cache 'timeout '= seconds
      }
      {line
        LogDecl
      }
      {line
        {or
          'accouting 'authorization 'accounting
        }
        'log = logName
      }
      {line
        'pap
        {or
          {line
            'backend '= 'mavis
            {optx
              'prefetch
            }
          }
          {line
            'password '=
            {or
              'pap 'login
            }
          }
        }
      }
      {line
        'login 'backend '= 'mavis
        {toploop
          {optx
            {or
              {line
                'prefetch
              }
              {line
                'chalresp
              }
              {line
                'chpass
              }
            }
          }
        }
      }
      {line
        'ms-chap
        {or
          {line
            'backend '= 'mavis
            {optx
              'prefetch
            }
          }
        }
      }
      {line
        'password 'acl '= aclName
      }
      {line
        'warning 'period '= seconds
      }
      {line
        'connection 'timeout '= seconds
      }
      {line
        'context 'timeout '= seconds
      }
      {line
        'time 'zone '= timezone
      }
      {line
        'enable 'user 'acl '= aclName
      }
      {line
        'rewrite name '= rewriteDecl
      }
      {line
        HostDecl
      }
      {line
        NetDecl
      }
      {line
        ACLDecl
      }
      {line
        GroupDecl
      }
      {line
        UserDecl
      }
      {line
        'ruleset '{
        rule
        '}
      }
      {line
        'realm subRealmName '{ RealmAttr '}
      }
      {line
        'parent '= realmName
      }
      {line
        'password 'max-attempts '= number
      }
      {line
        'password 'expiry 'warning '= number
      }
      {line
        'max-rounds '= number
      }
      {line
        'dns
        {or
          {line
            'preload
            {or
              {line
                'file '= FileName
              }
              {line
                'address '= ipAddress
              }
            }
          }
          {line
            'timeout '= seconds
          }
          {line
            'cache 'period '= seconds
          }
          {line
            'servers '= quotedString
          }
          {line
            'reverse-lookup
            {optx
              {line
                'nac
              }
              {line
                'nas
              }
            }
            '=
            {or
              'yes 'no
            }
          }
          {line
            'message messageName '= string
          }
        }
      }
      {line
        'haproxy auto-detect '=
        {or
          'yes 'no
        }
      }
    }
  }
}
