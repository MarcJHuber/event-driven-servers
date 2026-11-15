# DeviceAttr
set all_graphs {
  tac_plus-ng/DeviceAttr
  {or
    {line
      EnableExpr
    }
    {line
      {or
        {line
          'key
        }
        {line
          'radius.key
        }
      }
      {optx
        'warn
        {optx
          {or
            yyyy-mm-dd secondsSinceTheEpoch
          }
        }
      }
      '=
      {optx
        {or
          {line
            'clear
          }
          {line
            '6
          }
          {line
            '7
          }
        }
      }
      string
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
      'address
      {or
        {line 
          '= CIDR
        }
        {line
          'file '= filePath
        }
      }
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
      'session 'timeout '= seconds
    }
    {line
      'ccntext 'timeout '= seconds
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
      'device subDeviceName '{ DeviceAttr '}
    }
    {line
      'parent '= devicName
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
      'script '{ tacAction '}
    }
    {line
      'script = aclName
    }
    {line
      'dns
      {or
        {line
          'timeout '= seconds
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
          '
          {or
            'yes 'no
          }
        }
      }
    }
    {line
      'message messageName '= string
    }
    {line
      'tag '= tagName
      {optx
        {toploop
          ', tagName
        }
      }
    }
    {line
      'target-realm '= realm
    }
    {line
      'mavis 'backend '=
      {or
        'yes 'no
      }
    }
    {line
      Debug
    }
  }
}
