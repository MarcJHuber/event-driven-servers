# RewriteExpr
set all_graphs {
  ftpd/RewriteExpr
  {line
    'rewrite perlRegex perlRegexReplacement
    {optx
      {or
        'Last 'Next 'Reject
      }
    }
  }
}
