# TimeDecl
set all_graphs {
  tac_plus-ng/TimespecDecl
  {line
    'timespec '= timespecName '{
    {loop
      {or
        cronStyleTime uucpStyleTime
      }
    }
    '}
  }
}
