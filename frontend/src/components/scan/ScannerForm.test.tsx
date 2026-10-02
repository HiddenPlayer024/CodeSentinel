import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { ScannerForm } from './ScannerForm';
import { BrowserRouter } from 'react-router-dom';
import * as api from '../../api/codesentinel';

vi.mock('../../api/codesentinel', () => ({
  scanGithub: vi.fn(),
}));

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

describe('ScannerForm', () => {
  it('validates github URL before submitting', async () => {
    render(<BrowserRouter><ScannerForm /></BrowserRouter>);
    
    const input = screen.getByPlaceholderText(/github.com/i);
    const btn = screen.getByRole('button', { name: /scan repository/i });
    
    fireEvent.change(input, { target: { value: 'https://gitlab.com/test/repo' } });
    fireEvent.click(btn);
    
    expect(screen.getByText(/Please enter a valid github.com repository URL/i)).toBeInTheDocument();
    expect(api.scanGithub).not.toHaveBeenCalled();
  });

  it('submits valid URL and navigates to results', async () => {
    (api.scanGithub as any).mockResolvedValue({ id: '123', findings: [] });
    
    render(<BrowserRouter><ScannerForm /></BrowserRouter>);
    
    const input = screen.getByPlaceholderText(/github.com/i);
    const btn = screen.getByRole('button', { name: /scan repository/i });
    
    fireEvent.change(input, { target: { value: 'https://github.com/test/repo' } });
    fireEvent.click(btn);
    
    expect(screen.getByText(/ANALYZING REPOSITORY/i)).toBeInTheDocument();
    
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/results/latest', { 
        state: { session: { id: '123', findings: [] } } 
      });
    });
  });
});
