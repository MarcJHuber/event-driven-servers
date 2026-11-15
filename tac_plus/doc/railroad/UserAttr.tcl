# UserAttr
set all_graphs {
  tac_plus/UserAttr
  {or
    {line
      {optx
        'password
      }
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
    }
    {line
      'password '= PasswdExpr
    }
    {line
      'password
      {optx
        Acl
      }
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
  }
}
