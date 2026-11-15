# UserAttr
set all_graphs {
  tac_plus-ng/UserAttr
  {or
    {line
      member '= groupName
      {optx
        {toploop
          ', groupName
        }
      }
    }
    {line
      EnableExpr
    }
    {line
      {optx
        'password
      }
      {or
        {line
          {or
            'login 'pap
          }
          {optx
            'fallback
          }
          '= PasswordExprHash
        }
        {line
          {or
            'chap 'ms-chap
          }
          '= PasswordExpr
        }
      }
    }
    {line
      'password
      '{
      {or
        {line
          {or
            'login 'pap
          }
          '= PasswordExprHash
        }
        {line
          {or
            'chap 'ms-chap
          }
          '= PasswordExpr
        }
      }
      '}
    }
    {line
      'alias '= alternateUserName
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
      'net netName '{ netAttr '}
    }
    
    {line
      'timeSpec timeSpecName '{ timeSpecAttr '}
    }
    
    {line
      'profile
      {or
        {line
          '{
          {line
            {loop profileAttr
            }
          }
          '}
        }
        {line
          '= profileName
        }
      }
    }
  }
}
