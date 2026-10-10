
import * as fs from 'fs';
export function readFile(filename: string) {
    return fs.readFileSync('/var/www/html/' + filename, 'utf8');
}
