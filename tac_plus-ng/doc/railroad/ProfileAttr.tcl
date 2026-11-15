# GroupAttr
set all_graphs {
  tac_plus-ng/ProfileAttr
  {or
    {line
      EnableExpr
    }
    {line
      'hushlogin '=
      {or
        'permit 'deny
      }
    }
    {line
      'profile subProfileName '{ ProfileAttr '}
    }
    {line
      'parent '= profileName
    }
    {line
      acl '{ TacAction '}
    }
    {line
      acl '= aclName
    }
    {line
      script '{ TacAction '}
    }
    {line
      script '= aclName
    }
    {line
      Debug
    }
  }
}
