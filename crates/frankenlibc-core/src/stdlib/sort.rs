//! Sorting and searching functions.

/// Generic qsort implementation.
/// `base`: the entire array as bytes.
/// `width`: size of each element in bytes.
/// `compare`: comparison function returning <0, 0, >0.
pub fn qsort<F>(base: &mut [u8], width: usize, compare: F)
where
    F: Fn(&[u8], &[u8]) -> i32 + Copy,
{
    if width == 0 || base.len() < width {
        return;
    }
    let num = base.len() / width;
    if num < 2 {
        return;
    }

    // Depth limit: 2 * floor(log2(num)). Prevents O(n^2) stack depth.
    let depth_limit = 2 * (usize::BITS - num.leading_zeros()) as usize;
    quicksort_safe(base, width, &compare, depth_limit);
}

fn quicksort_safe<F>(buffer: &mut [u8], width: usize, compare: &F, depth_limit: usize)
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let len = buffer.len();
    let count = len / width;
    if count < 2 {
        return;
    }

    // Fall back to insertion sort when recursion is too deep.
    if depth_limit == 0 {
        insertion_sort(buffer, width, compare);
        return;
    }

    // Partition
    let pivot_index = partition(buffer, width, compare);

    // Split at pivot.
    // Left is [0..pivot_index], right is [pivot_index..end].
    // Pivot element is at right[0..width].
    // Recurse on left and right[width..].
    let (left, right) = buffer.split_at_mut(pivot_index * width);

    quicksort_safe(left, width, compare, depth_limit - 1);
    if right.len() > width {
        quicksort_safe(&mut right[width..], width, compare, depth_limit - 1);
    }
}

fn partition<F>(buffer: &mut [u8], width: usize, compare: &F) -> usize
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let count = buffer.len() / width;
    let last = count - 1;

    // Median-of-three pivot selection: compare first, middle, and last
    // elements, then swap the median into the last position as pivot.
    if count >= 3 {
        let mid = count / 2;
        // Sort the three candidates so the median ends up in position `mid`.
        if compare(&buffer[0..width], &buffer[mid * width..(mid + 1) * width]) > 0 {
            swap_chunks(buffer, 0, mid, width);
        }
        if compare(&buffer[0..width], &buffer[last * width..(last + 1) * width]) > 0 {
            swap_chunks(buffer, 0, last, width);
        }
        if compare(
            &buffer[mid * width..(mid + 1) * width],
            &buffer[last * width..(last + 1) * width],
        ) > 0
        {
            swap_chunks(buffer, mid, last, width);
        }
        // Now first <= mid <= last. Swap median (mid) into pivot position (last).
        swap_chunks(buffer, mid, last, width);
    }

    let pivot_idx = last;

    let mut i = 0;
    for j in 0..pivot_idx {
        let cmp = {
            let (head, tail) = buffer.split_at(pivot_idx * width);
            let val_j = &head[j * width..(j + 1) * width];
            let pivot = &tail[0..width];
            compare(val_j, pivot)
        };

        if cmp <= 0 {
            swap_chunks(buffer, i, j, width);
            i += 1;
        }
    }
    swap_chunks(buffer, i, pivot_idx, width);
    i
}

fn swap_chunks(buffer: &mut [u8], i: usize, j: usize, width: usize) {
    if i == j {
        return;
    }
    let (head, tail) = if i < j {
        buffer.split_at_mut(j * width)
    } else {
        buffer.split_at_mut(i * width)
    };

    let first = if i < j {
        &mut head[i * width..(i + 1) * width]
    } else {
        &mut head[j * width..(j + 1) * width]
    };

    first.swap_with_slice(&mut tail[0..width]);
}

/// Insertion sort fallback for small or deeply-recursed subarrays.
fn insertion_sort<F>(buffer: &mut [u8], width: usize, compare: &F)
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let count = buffer.len() / width;
    for i in 1..count {
        let mut j = i;
        while j > 0 {
            let cmp = compare(
                &buffer[(j - 1) * width..j * width],
                &buffer[j * width..(j + 1) * width],
            );
            if cmp <= 0 {
                break;
            }
            swap_chunks(buffer, j - 1, j, width);
            j -= 1;
        }
    }
}

/// Generic bsearch implementation.
pub fn bsearch<'a, K, F>(key: &K, base: &'a [u8], width: usize, compare: F) -> Option<&'a [u8]>
where
    K: ?Sized,
    F: Fn(&K, &[u8]) -> i32,
{
    if width == 0 || base.len() < width {
        return None;
    }

    let count = base.len() / width;
    let mut low = 0;
    let mut high = count;

    while low < high {
        let mid = low + (high - low) / 2;
        let mid_elem = &base[mid * width..(mid + 1) * width];
        let cmp = compare(key, mid_elem);

        if cmp == 0 {
            return Some(mid_elem);
        } else if cmp < 0 {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    None
}
