# TimespecDecl
set all_graphs {
  tac_plus/TimespecDecl
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
