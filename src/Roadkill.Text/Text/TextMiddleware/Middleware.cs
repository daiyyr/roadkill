﻿using Roadkill.Text.Text.Menu;

namespace Roadkill.Text.Text.TextMiddleware
{
    public abstract class Middleware
    {
        public abstract PageHtml Invoke(PageHtml pageHtml);
    }
}