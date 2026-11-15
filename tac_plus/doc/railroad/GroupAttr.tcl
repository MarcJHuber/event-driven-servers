# GroupAttr
set all_graphs {
  tac_plus/GroupAttr
  {or
    {line
      EnableExpr
    }
    {line
      'valid
      {or
        'from 'until
      }
      '=
      {or
        yyyy-mm-dd secondsSinceTheEpoch
      }
    }
    {line
      'message '= string
    }
    {line
      'default 'service '=
      {or
        'permit 'deny
      }
    }
    {line
      'hushlogin '=
      {or
        'permit 'deny
      }
    }
    {line
      'prohibit 'service '= serviceName
    }
    {line
      'client
      {or
        {line
          '=
          {optx
            {or
              'permit 'deny
            }
          }
          {or
            CIDR hostName
          }
        }
        {line
          'regex '=
          {optx
            {or
              'permit 'deny
            }
          }
          regularExpression
        }
      }
    }
    {line
      'server '=
      {optx
        {or
          'permit 'deny
        }
      }
      {or
        CIDR hostName
      }
    }
    {line
      'member
      {optx
        Acl
      }
      '= groupName
      {optx
        '@
        {toploop
          {or
            CIDR hostName
          }
          ',
        }
      }
    }
    {line
      'nas 'restriction 'default '=
      {toploop
        {or
          CIDR hostName
        }
        ',
      }
    }
    {line
      'tag
      {optx
        Acl
      }
      '= groupName
    }
    {line
      'acl '=
      {optx
        {or
          'permit 'deny
        }
      }
      {optx
        'not
      }
      aclName
    }
    {line
      'mavis 'realm '= realmName
    }
    {line
      Debug
    }
  }
}
