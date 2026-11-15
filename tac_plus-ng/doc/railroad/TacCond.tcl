# TacCond
set all_graphs {
  tac_plus-ng/TacCond
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
        '&& '||
      }
      TacCond
      ')
    }
    {line
      {or 
        'cmd 'context 'port 'user 'user.original 'password 'vrf
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
      'type
      {or
        '== '!=
      }
      {or
        'authen 'author 'acct
      }
    }
    {line
      'device
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
      'nac
      {or
        '== '!=
      }
      netName
    }
    {line
      'nas
      {or
        '== '!=
      }
      {or
        deviceName netName
      }
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
      'time
      {or
        '== '!=
      }
      timeName
    }
    {line
      'acl
      {or
        '== '!=
      }
      aclName
    }
    {line
      'realm
      {or
        {line
          {or
            '== '!=
          }
          realmName
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
      'member 
      {or
        '== '!=
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
        'dn 'memberof
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
      'attr[
      attrName
      ']
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
      'authen-action 'authen-type 'authen-service 'authen-method
      {or
        '== '!=
      }
      string
    }
    {line
      {or
        'tls.conn.version 'tls.conn.cipher 'tls.peer.cert.issuer 'tls.peer.cert.subject 'tls.conn.cipher.strength 'tls.peer.cn 'tls.psk.identity
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
      ${variable}
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
      value
    }
  }
}
