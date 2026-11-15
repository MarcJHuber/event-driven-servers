# GroupAttr
set all_graphs {
  tac_plus-ng/GroupAttr
  {or
    {line
      GroupDecl
    }
    {line
      parent '= groupName
    }
    {line
      member '= groupName
      {optx
        {toploop
          ', groupName
        }
      }
    }
  }
}
