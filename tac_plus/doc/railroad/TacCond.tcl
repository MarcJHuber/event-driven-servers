# TacCond
set all_graphs {
  tac_plus/TacCond
  {or
    {line
      '! TacCond
    }
    {line
      '( TacCond ')
    }
    {line
      '( TacCond
      {or
        '&& '|| TacCond
      }
      ')
    }
    {line
      {or
        'cmd 'context 'port 'user 'password
      }
      {or
        {line
          {or
            '== '!=
          }
          value
        }
        {line
          {or
            '=~ '!~
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
        '== '!=
      }
      hostName
    }
    {line
      {or
        'nac 'nas 'nac-name 'nas-name 'nac-realm 'nas-realm 'aaa-realm
      }
      {or
        '=~ '!~
      }
      regEx
    }
    {line
      'time
      {or
        '== '!=
      }
      timespecName
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
