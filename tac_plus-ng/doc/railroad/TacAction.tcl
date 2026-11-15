# TacAction
set all_graphs {
  tac_plus-ng/TacAction
  {or
    {line
      'if TacCond TacAction
      {optx
        'else TacAction
      }
    }
    {line
      'context '= string
    }
    {line
      'label '= string
    }
    {line
      'message '= string
    }
    {line
      'profile '= profileName
    }
    {line
      'rewrite 'user '= rewriteRuleName
    }
    {line
      'permit
    }
    {line
      'deny
    }
    {line
      'return
    }
    {line
      'acl aclName
    }
    {line
      '{
      {loop
        TacAction
      }
      '}
    }
  }
}
