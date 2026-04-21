import { useContext } from 'react';
import { ThemeContext } from '../components/theme-provider';

export function useTheme() {
  return useContext(ThemeContext);
}
