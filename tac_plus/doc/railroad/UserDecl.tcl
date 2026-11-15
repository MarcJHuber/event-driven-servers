# UserDecl
set all_graphs {
  tac_plus/UserDecl
  {
    line 'user
    {optx
      'realm realmName
    }
    '= userName '{
    {line
      {
        toploop
        {or
          UserAttr GroupAttr ShellDecl ServiceDecl
        }
      }
    }
    '}
  }
}
