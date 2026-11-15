# GroupDecl
set all_graphs {
  tac_plus/GroupDecl
  {
    line 'group
    {optx
      'realm realmName
    }
    '= groupName '{
    {line
      {
        toploop
        {or
          GroupAttr GroupOnlyAttr ShellDecl ServiceDecl
        }
      }
    }
    '}
  }
}
