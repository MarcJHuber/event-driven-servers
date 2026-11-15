# TacAction
set all_graphs {
  tac_plus/TacAction
  {or
    {line
      'if TacCond TacAction
      {optx
        'else TacAction
      }
    }
    {line
      'context '= value
    }
    {line
      'message '= value
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
      '{
      {loop
        TacAction
      }
      '}
    }
  }
}
