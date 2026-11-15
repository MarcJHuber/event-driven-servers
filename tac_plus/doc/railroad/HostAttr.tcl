# HostAttr
set all_graphs {
  tac_plus/HostAttr
  {or
    {line
      'key
      {optx
        'warn
        {optx
          {or
            yyyy-mm-dd secondsSinceTheEpoch
          }
        }
      }
      '= string
    }
    {line
      'welcome 'banner
      {optx
        'fallback
      }
      '= string
    }
    {line
      'motd 'banner '= string
    }
    {line
      'failed 'authentication 'banner '= string
    }
    {line
      'reject 'banner '= string
    }
    {line
      'access 'acl '=
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
      'template '=
      {or
        'CIDR hostName
      }
    }
    {line
      'address '= 'CIDR
    }
    {line
      'name '= hostName
    }
    {line
      'usage '=
      {or
        'any 'all 'client 'server 'none 'group-membership
      }
    }
    {line
      'inherit '=
      {or
        'yes 'no
      }
    }
    {line
      'dns 'reverse-lookup '=
      {or
        'yes 'no
      }
    }
    {line
      'dns 'timeout '= seconds
    }
    {line
      'single-connect
      {optx
        'may-close
      }
      '=
      {or
        'yes 'no
      }
    }
    {line
      'connection 'timeout '= seconds
    }
    {line
      'aaa 'realm '= realmName
    }
    {line
      'authentication 'fallback '=
      {or
        'permit 'deny
      }
    }
    {line
      'pap 'password 'mapping '=
      {or
        'login 'pap
      }
    }
    {line
      'anonymous-enable '=
      {or
        'permit 'deny
      }
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
      }
    }
    {line
      'default user '= userName
    }
    {line
      'default group '= groupName
    }
    {line
      Debug
    }
  }
}
