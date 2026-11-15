# ACLExpr
set all_graphs {
  tac_plus-ng/ACLExpr
  {toploop
    {or
      {line
        {or
          'nac 'nas
        }
        {or
          {line
            '=
            {optx
              'not
            }
            {or
              deviceName CIDR
            }
          }
          {line
            {optx
              'dns
            }
            'regex '=
            {optx
              'not
            }
            regEx
          }
        }
      }
      {line
        {or
          'nac 'nas
        }
        {or
          {line
            {or
              '== '!=
            }
            {or
              deviceName CIDR
            }
          }
          {line
            {optx
              'dns
            }
            {or
              '=~ '!~
            }
            regEx
          }
        }
      }
      {line
        {or
          'nac-name 'nas-name
        }
        'regex '=
        {optx
          'not
        }
        regEx
      }
      {line
        {or
          'nac-name 'nas-name
        }
        {or
          '=~ '!~
        }
        regEx
      }
      {line
        'port 'regex '=
        {optx
          'not
        }
        regEx
      }
      {line
        'port
        {or
          '=~ '!~
        }
        regEx
      }
      {line
        'realm 'regex '=
        {optx
          'not
        }
        regEx
      }
      {line
        'realm
        {or
          '=~ '!~
        }
        regEx
      }
      {line
        'time '=
        {optx
          'not
        }
        timeSpecName
      }
      {line
        'time
        {optx
          '== '!=
        }
        timeSpecName
      }
      {line
        'acl '=
        {optx
          'not
        }
        aclName
      }
      {line
        'acl
        {or
          '== '!=
        }
        aclName
      }
    }
  }
}
