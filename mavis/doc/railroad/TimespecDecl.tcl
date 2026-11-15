# TimespecDecl
set all_graphs {
  mavis/TimespecDecl
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
