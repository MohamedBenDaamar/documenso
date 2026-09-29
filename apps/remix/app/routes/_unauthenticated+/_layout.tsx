import backgroundPattern from '@documenso/assets/images/background-pattern.png';
import { SOURCE_CODE_URL } from '@documenso/lib/constants/app';
import { Trans } from '@lingui/react/macro';
import { Outlet } from 'react-router';

export default function Layout() {
  return (
    <main className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden px-4 py-12 md:p-12 lg:p-24">
      <div>
        <div className="absolute -inset-[min(600px,max(400px,60vw))] -z-[1] flex items-center justify-center opacity-70">
          <img
            src={backgroundPattern}
            alt="background pattern"
            className="dark:brightness-95 dark:contrast-[70%] dark:invert dark:sepia"
            style={{
              mask: 'radial-gradient(rgba(255, 255, 255, 1) 0%, transparent 80%)',
              WebkitMask: 'radial-gradient(rgba(255, 255, 255, 1) 0%, transparent 80%)',
            }}
          />
        </div>

        <div className="relative w-full">
          <Outlet />
        </div>
      </div>

      <footer className="relative mt-12 text-center text-muted-foreground text-xs">
        <Trans>
          This instance runs a modified version of Documenso.{' '}
          <a href={SOURCE_CODE_URL} className="underline underline-offset-2" target="_blank" rel="noreferrer">
            Source code
          </a>
        </Trans>
      </footer>
    </main>
  );
}
