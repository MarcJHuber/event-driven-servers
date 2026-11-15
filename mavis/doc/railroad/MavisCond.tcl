# MavisCond
set all_graphs {
  mavis/MavisCond
  {or
    {line
      '! MavisCond
    }
    {line
      '( MavisCond ')
    }
    {line
      MavisCond
      {or
        '&& '||
      }
      MavisCond
    }
    {line
      {or
        'defined 'undef
      }
      {or
        {line
          '( MavisAttribute ')
        }
        MavisAttribute
      }
    }
    {line
      MavisAttribute
      {or
        '== '!=
      }
      {or
        MavisAttribute value
      }
    }
    {line
      MavisAttribute
      {or
        '=~ '!~
      }
      regEx
    }
  }
}
